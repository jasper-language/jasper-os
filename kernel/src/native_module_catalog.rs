//! Native module lifecycle adapter for the live Assembly and ServiceCatalog.
//!
//! The kernel-core registry owns installation identity and dependency order.
//! This adapter delegates activation to `Assembly::start_runtime_module`,
//! which updates the authoritative runtime state, audits the complete
//! publication mask, and only then notifies the ServiceCatalog event source.

use kernel_core::native_module_lifecycle::{BindingModuleLifecycle, ModuleLifecycle, ModuleStatus};

pub(crate) struct ServiceCatalogModuleLifecycle {
    bindings: BindingModuleLifecycle<'static>,
}

impl ServiceCatalogModuleLifecycle {
    pub(crate) fn new() -> Self {
        Self {
            bindings: BindingModuleLifecycle::new(crate::assembly::bindings()),
        }
    }
}

impl ModuleLifecycle for ServiceCatalogModuleLifecycle {
    fn activate(&mut self, status: ModuleStatus) -> Result<(), &'static str> {
        self.bindings.validate(status)?;
        crate::assembly::start_runtime_module(status.name.as_str()).map_err(|error| error.name())
    }

    fn deactivate(&mut self, status: ModuleStatus) -> Result<(), &'static str> {
        crate::assembly::stop(status.name.as_str()).map_err(|error| error.name())
    }

    fn can_deactivate(&self, status: ModuleStatus) -> bool {
        self.bindings.validate(status).is_ok()
    }
}
