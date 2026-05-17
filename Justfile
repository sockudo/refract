set shell := ["sh", "-cu"]

fmt:
    cargo xtask fmt

lint:
    cargo xtask lint

test:
    cargo xtask test

bench:
    cargo xtask bench

fuzz:
    cargo xtask fuzz

coverage:
    cargo xtask coverage

audit:
    cargo xtask audit

deny:
    cargo xtask deny

msrv:
    cargo xtask msrv

preflight:
    cargo xtask preflight

release:
    cargo xtask release

install-hooks:
    cargo xtask install-hooks

