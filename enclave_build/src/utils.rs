// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bollard::errors::Error;
use bollard::secret::{BuildInfo, CreateImageInfo};
use futures::stream::StreamExt;
use futures::Stream;
use log::{error, info};

pub trait StreamItem {
    fn error(&self) -> Option<String>;
}

// Implement StreamItem for CreateImageInfo
impl StreamItem for CreateImageInfo {
    fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

// Implement StreamItem for BuildInfo
impl StreamItem for BuildInfo {
    fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

pub async fn handle_stream_output<T, U>(
    mut stream: impl Stream<Item = Result<T, Error>> + Unpin,
    error_type: U,
) -> Result<(), U>
where
    T: StreamItem + std::fmt::Debug,
{
    while let Some(item) = stream.next().await {
        match item {
            Ok(output) => {
                if let Some(err_msg) = output.error() {
                    error!("{:?}", err_msg);
                    return Err(error_type);
                } else {
                    info!("{:?}", output);
                }
            }
            Err(e) => {
                error!("{:?}", e);
                return Err(error_type);
            }
        }
    }

    Ok(())
}
