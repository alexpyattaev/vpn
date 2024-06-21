use color_eyre::eyre::{eyre, Result};
use futures::{future::JoinAll, Future};
use tokio::task::JoinHandle;

/// flattens the result of tokio::spawn such that it can be safely polled directly
pub async fn flatten<T>(handle: JoinHandle<Result<T>>) -> Result<T> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(eyre!("handling of future failed with error {}", err)),
    }
}

/// merge outputs from a JoinAll into one result, returning the first encountered error.
pub async fn merge(futs: JoinAll<impl Future<Output = Result<()>>>) -> Result<()> {
    let a = futs.await.into_iter().find(|v| v.is_err());
    match a {
        None => Ok(()),
        Some(Err(v)) => Err(v),
        Some(Ok(_)) => unreachable!("This is not possible"),
    }
}
