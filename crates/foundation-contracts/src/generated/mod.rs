pub mod northstar {
    pub mod common {
        pub mod v1 {
            include!("northstar.common.v1.rs");
        }
    }
    pub mod delivery {
        pub mod v1 {
            include!("northstar.delivery.v1.rs");
        }
    }
    pub mod events {
        pub mod v1 {
            include!("northstar.events.v1.rs");
        }
    }
    pub mod identity {
        pub mod v1 {
            include!("northstar.identity.v1.rs");
        }
    }
    pub mod ingress {
        pub mod v1 {
            include!("northstar.ingress.v1.rs");
        }
    }
    pub mod registry {
        pub mod v1 {
            include!("northstar.registry.v1.rs");
        }
    }
    pub mod session {
        pub mod v1 {
            include!("northstar.session.v1.rs");
        }
    }
    pub mod security {
        pub mod v1 {
            include!("northstar.security.v1.rs");
        }
    }
}
