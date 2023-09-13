use crate::chunks::*;
use log::{error, info};
use std::io::{Seek, SeekFrom};
use symphonia_core::{
    audio::Channels,
    codecs::*,
    errors::{decode_error, end_of_stream_error, unsupported_error, Result},
    formats::{Cue, FormatOptions, FormatReader, Packet, SeekMode, SeekTo, SeekedTo, Track},
    io::{MediaSource, MediaSourceStream, ReadBytes},
    meta::{Metadata, MetadataLog},
    probe::{Descriptor, Instantiate, QueryDescriptor},
    support_format,
    units::TimeBase,
};

const MAX_FRAMES_PER_PACKET: u64 = 1152;

/// Core Audio Format (CAF) format reader.
///
/// `CafReader` implements a demuxer for Core Audio Format containers.
pub struct CafReader {
    reader: MediaSourceStream,
    tracks: Vec<Track>,
    cues: Vec<Cue>,
    metadata: MetadataLog,
    data_start_pos: u64,
    data_len: Option<u64>,
    packet_info: PacketInfo,
}

enum PacketInfo {
    Unknown,
    Uncompressed { bytes_per_packet: u32 },
    Compressed { packets: Vec<CafPacket>, current_packet_index: usize },
}

impl QueryDescriptor for CafReader {
    fn query() -> &'static [Descriptor] {
        &[support_format!("caf", "Core Audio Format", &["caf"], &["audio/x-caf"], &[b"caff"])]
    }

    fn score(_context: &[u8]) -> u8 {
        255
    }
}

impl FormatReader for CafReader {
    fn try_new(source: MediaSourceStream, _options: &FormatOptions) -> Result<Self> {
        let mut reader = Self {
            reader: source,
            tracks: vec![],
            cues: vec![],
            metadata: MetadataLog::default(),
            data_start_pos: 0,
            data_len: None,
            packet_info: PacketInfo::Unknown,
        };

        reader.check_file_header()?;
        let codec_params = reader.read_chunks()?;

        reader.tracks.push(Track::new(0, codec_params));

        Ok(reader)
    }

    fn next_packet(&mut self) -> Result<Packet> {
        match &mut self.packet_info {
            PacketInfo::Uncompressed { bytes_per_packet } => {
                let pos = self.reader.pos();
                let data_pos = pos - self.data_start_pos;

                let bytes_per_packet = *bytes_per_packet as u64;
                let max_bytes_to_read = bytes_per_packet * MAX_FRAMES_PER_PACKET;

                let bytes_remaining = if let Some(data_len) = self.data_len {
                    data_len - data_pos
                } else {
                    max_bytes_to_read
                };

                if bytes_remaining == 0 {
                    return end_of_stream_error();
                }

                let bytes_to_read = max_bytes_to_read.min(bytes_remaining);
                let packet_duration = bytes_to_read / bytes_per_packet;
                let packet_timestamp = data_pos / bytes_per_packet;
                let buffer = self.reader.read_boxed_slice(bytes_to_read as usize)?;
                // dbg!(packet_timestamp);
                // dbg!(packet_duration);
                Ok(Packet::new_from_boxed_slice(0, packet_timestamp, packet_duration, buffer))
            }
            PacketInfo::Compressed { packets, ref mut current_packet_index } => {
                if let Some(packet) = packets.get(*current_packet_index) {
                    // dbg!(packet);
                    // dbg!(self.reader.pos());
                    *current_packet_index += 1;
                    let buffer = self.reader.read_boxed_slice(packet.size as usize)?;
                    Ok(Packet::new_from_boxed_slice(0, packet.start_frame, packet.frames, buffer))
                } else {
                    if *current_packet_index == packets.len() {
                        end_of_stream_error()
                    } else {
                        decode_error("Invalid packet index")
                    }
                }
            }
            PacketInfo::Unknown => decode_error("Missing packet info"),
        }
    }

    fn metadata(&mut self) -> Metadata<'_> {
        self.metadata.metadata()
    }

    fn cues(&self) -> &[Cue] {
        &self.cues
    }

    fn tracks(&self) -> &[Track] {
        &self.tracks
    }

    fn seek(&mut self, _mode: SeekMode, _to: SeekTo) -> Result<SeekedTo> {
        unimplemented!();
    }

    fn into_inner(self: Box<Self>) -> MediaSourceStream {
        self.reader
    }
}

impl CafReader {
    fn check_file_header(&mut self) -> Result<()> {
        let file_type = self.reader.read_quad_bytes()?;
        if file_type != *b"caff" {
            return unsupported_error("missing 'caff' stream marker");
        }

        let file_version = self.reader.read_be_u16()?;
        if file_version != 1 {
            error!("unsupported file version ({file_version})");
            return unsupported_error("unsupported file version");
        }

        // Ignored in CAF v1
        let _file_flags = self.reader.read_be_u16()?;

        Ok(())
    }

    fn read_audio_description_chunk(
        &mut self,
        desc: &AudioDescription,
        codec_params: &mut CodecParameters,
    ) -> Result<()> {
        codec_params
            .for_codec(desc.codec_type()?)
            .with_sample_rate(desc.sample_rate as u32)
            .with_time_base(TimeBase::new(1, desc.sample_rate as u32))
            .with_bits_per_sample(desc.bits_per_channel)
            .with_bits_per_coded_sample((desc.bytes_per_packet * 8) / desc.channels_per_frame);

        match desc.channels_per_frame {
            0 => {
                return decode_error("channel count is zero");
            }
            1 => {
                codec_params.with_channels(Channels::FRONT_LEFT);
            }
            2 => {
                codec_params.with_channels(Channels::FRONT_LEFT | Channels::FRONT_RIGHT);
            }
            n => {
                // When the channel count is >2 then enable the first N channels.
                // This can/should be overridden when parsing the channel layout chunk.
                match Channels::from_bits(((1u64 << n as u64) - 1) as u32) {
                    Some(channels) => {
                        codec_params.with_channels(channels);
                    }
                    None => {
                        return unsupported_error("unsupported channel count");
                    }
                }
            }
        }

        if desc.format_is_compressed() {
            self.packet_info =
                PacketInfo::Compressed { packets: Vec::new(), current_packet_index: 0 };
        } else {
            codec_params
                .with_max_frames_per_packet(MAX_FRAMES_PER_PACKET)
                .with_frames_per_block(desc.frames_per_packet as u64);
            self.packet_info = PacketInfo::Uncompressed { bytes_per_packet: desc.bytes_per_packet }
        };

        Ok(())
    }

    fn read_chunks(&mut self) -> Result<CodecParameters> {
        use Chunk::*;

        let mut codec_params = CodecParameters::new();
        let mut audio_description = None;

        loop {
            match Chunk::read(&mut self.reader, &audio_description)? {
                Some(AudioDescription(desc)) => {
                    if audio_description.is_some() {
                        return decode_error("additional Audio Description chunk");
                    }
                    self.read_audio_description_chunk(&desc, &mut codec_params)?;
                    audio_description = Some(desc);
                }
                Some(AudioData(data)) => {
                    self.data_start_pos = data.start_pos;
                    self.data_len = data.data_len;
                    if let Some(data_len) = self.data_len {
                        match &self.packet_info {
                            PacketInfo::Uncompressed { bytes_per_packet } => {
                                codec_params.with_n_frames(data_len / *bytes_per_packet as u64);
                            }
                            _ => {}
                        }
                    }
                }
                Some(ChannelLayout(layout)) => {
                    if let Some(channels) = layout.channels() {
                        codec_params.channels = Some(channels);
                    } else {
                        // Don't error if the layout doesn't correspond directly to a Symphonia
                        // layout, the channels bitmap was set after the audio description was read
                        // to match the number of channels, and that's probably OK.
                        info!("couldn't convert the channel layout into a channel bitmap");
                    }
                }
                Some(PacketTable(table)) => match &mut self.packet_info {
                    PacketInfo::Compressed { ref mut packets, .. } => {
                        codec_params.with_n_frames(table.valid_frames as u64);
                        *packets = table.packets;
                    }
                    _ => {}
                },
                Some(MagicCookie(data)) => {
                    codec_params.with_extra_data(data);
                }
                Some(Free) | None => {}
            }

            if audio_description.is_none() {
                error!("missing audio description chunk");
                return decode_error("missing audio description chunk");
            }

            if let Some(byte_len) = self.reader.byte_len() {
                if self.reader.pos() == byte_len {
                    // If we've reached the end of the file, then the Audio Data chunk should have
                    // had a defined size, and we should seek to the start of the audio data.
                    if self.data_len.is_some() {
                        self.reader.seek(SeekFrom::Start(self.data_start_pos))?;
                    }
                    break;
                }
            }
        }

        Ok(codec_params)
    }
}
