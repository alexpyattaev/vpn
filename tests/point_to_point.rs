use color_eyre::Result;
use itertools::Itertools;
use std::process::{Command, Output};

fn ip(args: &str) -> Command {
    let mut c = Command::new("ip");
    c.args(args.split(" "));
    c
}
fn print_command(c: &Command) {
    let args: String = c.get_args().map(|e| e.to_str().unwrap()).join(" ");
    println!("Running {} {}", c.get_program().to_str().unwrap(), args)
}

trait Entity {
    fn teardown(&mut self) -> Result<Output>;
    fn set_up(&mut self) -> Result<Output>;
}

impl Drop for NS {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

#[derive(Debug)]
struct NS {
    name: String,
}

impl Entity for NS {
    fn teardown(&mut self) -> Result<Output> {
        let mut c = ip(&format!("netns del {}", self.name));
        print_command(&c);
        Ok(c.output()?)
    }

    fn set_up(&mut self) -> Result<Output> {
        let mut c = ip(&format!("netns add {}", self.name));
        print_command(&c);
        Ok(c.output()?)
    }
}

#[derive(Debug)]
struct Bridge {
    name: String,
}
impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

impl Entity for Bridge {
    fn set_up(&mut self) -> Result<Output> {
        let mut c = ip(&format!("link add name {} type bridge", self.name));
        print_command(&c);
        Ok(c.output()?)
    }

    fn teardown(&mut self) -> Result<Output> {
        let mut c = ip(&format!("link del {}", self.name));
        print_command(&c);
        Ok(c.output()?)
    }
}

//ip l add name br0 type bridge

//#[test]
fn main() -> Result<()> {
    let mut ns_a = NS {
        name: "A".to_owned(),
    };
    let mut ns_b = NS {
        name: "B".to_owned(),
    };
    let mut br_mon = Bridge {
        name: "monitor".to_owned(),
    };
    ns_a.set_up()?;
    ns_b.set_up()?;
    br_mon.set_up()?;

    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    println!("You typed {}", buf);
    Ok(())
}

// fn cleanup(){

// let cmds = r"ip link del veth_A
// ip link del veth_B
// ip netns del A
// ip netns del B";
// }

/*



alias IN_A="ip netns exec A"
alias IN_B="ip netns exec B"
# Virtual wire between namespaces
ip link add veth_A type veth peer name veth_B

ip link set dev veth_A netns A
IN_A ip link set lo up
IN_A ip link set veth_A up
IN_A ip a a 6.6.6.6/24 dev veth_A

ip link set dev veth_B netns B
IN_B ip link set lo up
IN_B ip link set veth_B up
IN_B ip a a 6.6.6.7/24 dev veth_B

*/
