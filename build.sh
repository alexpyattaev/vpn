cargo build --release || exit 1
#sudo setcap  CAP_NET_ADMIN+ep target/debug/vpn
sudo setcap  CAP_NET_ADMIN+ep target/release/vpn

