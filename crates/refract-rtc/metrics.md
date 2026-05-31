# refract-rtc metrics

All metrics are emitted outside packet hot loops by the owning core. Labels are
bounded to enum-like values and never include peer identifiers, room identifiers,
ICE credentials, SDP text, addresses, or codec fmtp strings.

| Name | Type | Unit | Cardinality bound | Description |
| --- | --- | --- | --- | --- |
| `refract_rtc_sdp_offer_total` | counter | offers | `role=offer`, `codec_set` bucket only | SDP offers generated for the supported codec matrix. |
| `refract_rtc_sdp_answer_total` | counter | answers | `role=answer`, `codec_set` bucket only | SDP answers generated for the supported codec matrix. |
| `refract_rtc_sdp_parse_error_total` | counter | errors | `error_code` from `RtcError`, bounded by enum variants | Rejected SDP inputs. |
| `refract_rtc_ice_restart_total` | counter | restarts | no dynamic labels | ICE restart attempts started by this crate. |
| `refract_rtc_ice_state_total` | counter | transitions | `state` in `{new,checking,connected,disconnected}` | Normalized ICE state transitions from str0m. |
| `refract_rtc_str0m_transmit_queue_depth` | gauge | packets | no dynamic labels | Pending str0m `Transmit` items retained for the socket driver. |
| `refract_rtc_event_queue_depth` | gauge | events | no dynamic labels | Pending normalized RTC events retained for the owning core. |
| `refract_rtc_media_ingress_total` | counter | packets | `srtp_boundary` in `{refract-srtp,str0m}` | RTP packets accepted by the refract media path. |
