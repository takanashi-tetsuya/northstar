// @generated
/// Generated client implementations.
pub mod session_directory_service_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct SessionDirectoryServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl SessionDirectoryServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> SessionDirectoryServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> SessionDirectoryServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            SessionDirectoryServiceClient::new(
                InterceptedService::new(inner, interceptor),
            )
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        pub async fn bind_session(
            &mut self,
            request: impl tonic::IntoRequest<super::BindSessionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::BindSessionResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/northstar.session.v1.SessionDirectoryService/BindSession",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "northstar.session.v1.SessionDirectoryService",
                        "BindSession",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn renew_lease(
            &mut self,
            request: impl tonic::IntoRequest<super::RenewLeaseRequest>,
        ) -> std::result::Result<
            tonic::Response<super::RenewLeaseResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/northstar.session.v1.SessionDirectoryService/RenewLease",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "northstar.session.v1.SessionDirectoryService",
                        "RenewLease",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn resume_fence(
            &mut self,
            request: impl tonic::IntoRequest<super::ResumeFenceRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ResumeFenceResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/northstar.session.v1.SessionDirectoryService/ResumeFence",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "northstar.session.v1.SessionDirectoryService",
                        "ResumeFence",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn prepare_resume(
            &mut self,
            request: impl tonic::IntoRequest<super::PrepareResumeRequest>,
        ) -> std::result::Result<
            tonic::Response<super::PrepareResumeResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/northstar.session.v1.SessionDirectoryService/PrepareResume",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "northstar.session.v1.SessionDirectoryService",
                        "PrepareResume",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn commit_resume(
            &mut self,
            request: impl tonic::IntoRequest<super::CommitResumeRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CommitResumeResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/northstar.session.v1.SessionDirectoryService/CommitResume",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "northstar.session.v1.SessionDirectoryService",
                        "CommitResume",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn resolve_targets(
            &mut self,
            request: impl tonic::IntoRequest<super::ResolveTargetsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ResolveTargetsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/northstar.session.v1.SessionDirectoryService/ResolveTargets",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "northstar.session.v1.SessionDirectoryService",
                        "ResolveTargets",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn validate_assertion(
            &mut self,
            request: impl tonic::IntoRequest<super::ValidateAssertionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ValidateAssertionResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/northstar.session.v1.SessionDirectoryService/ValidateAssertion",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "northstar.session.v1.SessionDirectoryService",
                        "ValidateAssertion",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn revoke_account_sessions(
            &mut self,
            request: impl tonic::IntoRequest<super::RevokeAccountSessionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::RevokeAccountSessionsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/northstar.session.v1.SessionDirectoryService/RevokeAccountSessions",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "northstar.session.v1.SessionDirectoryService",
                        "RevokeAccountSessions",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn close_session(
            &mut self,
            request: impl tonic::IntoRequest<super::CloseSessionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CloseSessionResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/northstar.session.v1.SessionDirectoryService/CloseSession",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "northstar.session.v1.SessionDirectoryService",
                        "CloseSession",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod session_directory_service_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with SessionDirectoryServiceServer.
    #[async_trait]
    pub trait SessionDirectoryService: Send + Sync + 'static {
        async fn bind_session(
            &self,
            request: tonic::Request<super::BindSessionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::BindSessionResponse>,
            tonic::Status,
        >;
        async fn renew_lease(
            &self,
            request: tonic::Request<super::RenewLeaseRequest>,
        ) -> std::result::Result<
            tonic::Response<super::RenewLeaseResponse>,
            tonic::Status,
        >;
        async fn resume_fence(
            &self,
            request: tonic::Request<super::ResumeFenceRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ResumeFenceResponse>,
            tonic::Status,
        >;
        async fn prepare_resume(
            &self,
            request: tonic::Request<super::PrepareResumeRequest>,
        ) -> std::result::Result<
            tonic::Response<super::PrepareResumeResponse>,
            tonic::Status,
        >;
        async fn commit_resume(
            &self,
            request: tonic::Request<super::CommitResumeRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CommitResumeResponse>,
            tonic::Status,
        >;
        async fn resolve_targets(
            &self,
            request: tonic::Request<super::ResolveTargetsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ResolveTargetsResponse>,
            tonic::Status,
        >;
        async fn validate_assertion(
            &self,
            request: tonic::Request<super::ValidateAssertionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ValidateAssertionResponse>,
            tonic::Status,
        >;
        async fn revoke_account_sessions(
            &self,
            request: tonic::Request<super::RevokeAccountSessionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::RevokeAccountSessionsResponse>,
            tonic::Status,
        >;
        async fn close_session(
            &self,
            request: tonic::Request<super::CloseSessionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CloseSessionResponse>,
            tonic::Status,
        >;
    }
    #[derive(Debug)]
    pub struct SessionDirectoryServiceServer<T: SessionDirectoryService> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    impl<T: SessionDirectoryService> SessionDirectoryServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>>
    for SessionDirectoryServiceServer<T>
    where
        T: SessionDirectoryService,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            match req.uri().path() {
                "/northstar.session.v1.SessionDirectoryService/BindSession" => {
                    #[allow(non_camel_case_types)]
                    struct BindSessionSvc<T: SessionDirectoryService>(pub Arc<T>);
                    impl<
                        T: SessionDirectoryService,
                    > tonic::server::UnaryService<super::BindSessionRequest>
                    for BindSessionSvc<T> {
                        type Response = super::BindSessionResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::BindSessionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SessionDirectoryService>::bind_session(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = BindSessionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/northstar.session.v1.SessionDirectoryService/RenewLease" => {
                    #[allow(non_camel_case_types)]
                    struct RenewLeaseSvc<T: SessionDirectoryService>(pub Arc<T>);
                    impl<
                        T: SessionDirectoryService,
                    > tonic::server::UnaryService<super::RenewLeaseRequest>
                    for RenewLeaseSvc<T> {
                        type Response = super::RenewLeaseResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RenewLeaseRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SessionDirectoryService>::renew_lease(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RenewLeaseSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/northstar.session.v1.SessionDirectoryService/ResumeFence" => {
                    #[allow(non_camel_case_types)]
                    struct ResumeFenceSvc<T: SessionDirectoryService>(pub Arc<T>);
                    impl<
                        T: SessionDirectoryService,
                    > tonic::server::UnaryService<super::ResumeFenceRequest>
                    for ResumeFenceSvc<T> {
                        type Response = super::ResumeFenceResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ResumeFenceRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SessionDirectoryService>::resume_fence(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ResumeFenceSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/northstar.session.v1.SessionDirectoryService/PrepareResume" => {
                    #[allow(non_camel_case_types)]
                    struct PrepareResumeSvc<T: SessionDirectoryService>(pub Arc<T>);
                    impl<
                        T: SessionDirectoryService,
                    > tonic::server::UnaryService<super::PrepareResumeRequest>
                    for PrepareResumeSvc<T> {
                        type Response = super::PrepareResumeResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::PrepareResumeRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SessionDirectoryService>::prepare_resume(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = PrepareResumeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/northstar.session.v1.SessionDirectoryService/CommitResume" => {
                    #[allow(non_camel_case_types)]
                    struct CommitResumeSvc<T: SessionDirectoryService>(pub Arc<T>);
                    impl<
                        T: SessionDirectoryService,
                    > tonic::server::UnaryService<super::CommitResumeRequest>
                    for CommitResumeSvc<T> {
                        type Response = super::CommitResumeResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CommitResumeRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SessionDirectoryService>::commit_resume(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CommitResumeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/northstar.session.v1.SessionDirectoryService/ResolveTargets" => {
                    #[allow(non_camel_case_types)]
                    struct ResolveTargetsSvc<T: SessionDirectoryService>(pub Arc<T>);
                    impl<
                        T: SessionDirectoryService,
                    > tonic::server::UnaryService<super::ResolveTargetsRequest>
                    for ResolveTargetsSvc<T> {
                        type Response = super::ResolveTargetsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ResolveTargetsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SessionDirectoryService>::resolve_targets(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ResolveTargetsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/northstar.session.v1.SessionDirectoryService/ValidateAssertion" => {
                    #[allow(non_camel_case_types)]
                    struct ValidateAssertionSvc<T: SessionDirectoryService>(pub Arc<T>);
                    impl<
                        T: SessionDirectoryService,
                    > tonic::server::UnaryService<super::ValidateAssertionRequest>
                    for ValidateAssertionSvc<T> {
                        type Response = super::ValidateAssertionResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ValidateAssertionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SessionDirectoryService>::validate_assertion(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ValidateAssertionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/northstar.session.v1.SessionDirectoryService/RevokeAccountSessions" => {
                    #[allow(non_camel_case_types)]
                    struct RevokeAccountSessionsSvc<T: SessionDirectoryService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: SessionDirectoryService,
                    > tonic::server::UnaryService<super::RevokeAccountSessionsRequest>
                    for RevokeAccountSessionsSvc<T> {
                        type Response = super::RevokeAccountSessionsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RevokeAccountSessionsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SessionDirectoryService>::revoke_account_sessions(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RevokeAccountSessionsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/northstar.session.v1.SessionDirectoryService/CloseSession" => {
                    #[allow(non_camel_case_types)]
                    struct CloseSessionSvc<T: SessionDirectoryService>(pub Arc<T>);
                    impl<
                        T: SessionDirectoryService,
                    > tonic::server::UnaryService<super::CloseSessionRequest>
                    for CloseSessionSvc<T> {
                        type Response = super::CloseSessionResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CloseSessionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as SessionDirectoryService>::close_session(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = CloseSessionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", tonic::Code::Unimplemented as i32)
                                .header(
                                    http::header::CONTENT_TYPE,
                                    tonic::metadata::GRPC_CONTENT_TYPE,
                                )
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: SessionDirectoryService> Clone for SessionDirectoryServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    impl<T: SessionDirectoryService> tonic::server::NamedService
    for SessionDirectoryServiceServer<T> {
        const NAME: &'static str = "northstar.session.v1.SessionDirectoryService";
    }
}
