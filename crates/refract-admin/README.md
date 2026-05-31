# refract-admin

Administrative API surface for drain, diagnostics, and online operational actions.

Stage 1 defaults to UNIX-domain-socket-only administration with peer credential
authorization. The crate is runtime independent: the compio owner mounts the API
on a socket and passes uid/gid credentials into `AdminApi::handle`.

Implemented operations include graceful/fast drain, reload acknowledgement,
stats, paginated sessions, privacy-redacted session details, session kick,
bounded debug profile requests, log-level updates, and capabilities discovery.
