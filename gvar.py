ERROR_SCRIPT_DESTROYED = "script has been destroyed"

frida_instrument = None
enumerate_ranges = []
is_frida_attached = False
remote = False
list_modules = []
arch = None

is_hex_edit_mode = False
hex_edited = []

current_frame_block_number = 0
current_frame_start_address = ''

current_mem_scan_hex_view_result = ''

scan_progress_ratio = 0

dump_module_name = ''

visited_address = []

frida_portal_mode = False
frida_portal_cluster_port = 27052
frida_portal_controller_port = 27042
