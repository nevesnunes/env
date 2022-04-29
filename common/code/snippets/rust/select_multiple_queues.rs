use std::time::Duration;

use tokio::{sync::mpsc, time::sleep};

#[tokio::main]
async fn main() {
    let (tx1, mut rx1) = mpsc::channel::<u64>(128);
    let (tx2, mut rx2) = mpsc::channel::<u64>(128);

    let work = move |tx: mpsc::Sender<u64>, val: u64| {
        tokio::spawn(async move {
            for _ in 0..3 {
                let _ = tx.send(val).await;
                sleep(Duration::from_millis(200)).await;
            }
        });
    };
    work(tx1, 1);
    work(tx2, 2);

    loop {
        tokio::select! {
            Some(x) = rx1.recv() => println!("{x}"),
            Some(x) = rx2.recv() => println!("{x}"),
            // if idle for 500ms, exit (so the Rust playground won't time out)
            _ = sleep(Duration::from_millis(500)) => break,
        }
    }
}
