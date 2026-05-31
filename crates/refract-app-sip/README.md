# refract-app-sip

SIP bridge application boundary for versioned slow-path call control.

The crate is gated by the `app-sip` Cargo feature and implements bounded JSON
commands for invite, bye, DTMF, and call listing. It enforces bridge/admin
claims before mutating call state.
