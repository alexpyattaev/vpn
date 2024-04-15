su headhunter -c "cargo build --release "
setcap  CAP_NET_ADMIN+ep target/debug/vpn
setcap  CAP_NET_ADMIN+ep target/release/vpn

