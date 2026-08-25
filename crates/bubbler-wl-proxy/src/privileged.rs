/// Wayland interfaces the proxy hides from a sandbox when the
/// compositor has no `wp_security_context_v1` to hide them itself:
/// screen capture, clipboard management without focus, input injection,
/// session lock, overlays, foreign-toplevel and output control. The
/// class of privileged protocols, not one compositor's policy — the
/// names were read off what Hyprland 0.56 withholds from a
/// security-context client (31 of the 71 interfaces the same session
/// offers a plain one), which is the class spelled out.
///
/// Sorted, so a name added out of place is a diff a reader can follow.
/// Included by both `bubbler-wl-proxy` and `bubbler-core`, so the
/// denylist the proxy applies and the one core explains are one list.
pub const PRIVILEGED: &[&str] = &[
    "ext_data_control_manager_v1",
    "ext_foreign_toplevel_image_capture_source_manager_v1",
    "ext_foreign_toplevel_list_v1",
    "ext_image_copy_capture_manager_v1",
    "ext_output_image_capture_source_manager_v1",
    "ext_session_lock_manager_v1",
    "ext_workspace_manager_v1",
    "hyprland_ctm_control_manager_v1",
    "hyprland_focus_grab_manager_v1",
    "hyprland_global_shortcuts_manager_v1",
    "hyprland_input_capture_manager_v1",
    "hyprland_lock_notifier_v1",
    "hyprland_toplevel_export_manager_v1",
    "hyprland_toplevel_mapping_manager_v1",
    "vicinae_hotkey_manager_v1",
    "wp_content_type_manager_v1",
    "wp_drm_lease_device_v1",
    "wp_pointer_warp_v1",
    "wp_security_context_manager_v1",
    "xwayland_shell_v1",
    "zwlr_data_control_manager_v1",
    "zwlr_foreign_toplevel_manager_v1",
    "zwlr_gamma_control_manager_v1",
    "zwlr_layer_shell_v1",
    "zwlr_output_manager_v1",
    "zwlr_output_power_manager_v1",
    "zwlr_screencopy_manager_v1",
    "zwlr_virtual_pointer_manager_v1",
    "zwp_input_method_manager_v2",
    "zwp_virtual_keyboard_manager_v1",
    "zxdg_output_manager_v1",
];
