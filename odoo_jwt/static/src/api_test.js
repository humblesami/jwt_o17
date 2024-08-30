(function () {
    var api_url = '';
    var config_param_vals = {};
    let ls_prefix = 'odoo_17_jwt';
    let config_params = ['url'];
    let show_time = document.querySelector('.current_time');

    let js_utils = {
        addTrailingSlash: function (url_str) {
            if (url_str.endsWith('/')) {
                url_str += '/';
            }
            return url_str;
        },
        myTime: (dt = new Date()) => new Date(dt).toLocaleTimeString(),
        timer_running: 0,
        run_timer: () => {
            if(js_utils.timer_running) return;
            setInterval(()=> {
                show_time.innerHTML = js_utils.myTime();
            }, 1000);
            js_utils.timer_running = 1;
        },
        setLocalData: function (key, val){
            let prev_data = JSON.parse(localStorage.getItem(ls_prefix) || '{}');
            prev_data[key] = val;
            localStorage.setItem(ls_prefix, JSON.stringify(prev_data));
        },
        getLocalData: function (key){
            let prev_data = JSON.parse(localStorage.getItem(ls_prefix) || '{}');
            if(key == 'all_data') return prev_data;
            if(!key) throw('No key provided');
            return prev_data[key];
        }
    }
    function timingInfo(){
        js_utils.run_timer();
        let timeInfo = js_utils.getLocalData('time_info');
        document.querySelector('.value.login_time').innerHTML = js_utils.myTime(timeInfo.login_time);
        document.querySelector('.value.short_token_time').innerHTML = js_utils.myTime(timeInfo.short_token_time);
        document.querySelector('.value.long_token_time').innerHTML = js_utils.myTime(timeInfo.long_token_time);
        console.log(42222, timeInfo, document.querySelector('.value.short_term_token_span'));
        document.querySelector('.value.short_term_token_span').innerHTML = timeInfo.short_term_token_span;
        document.querySelector('.value.long_term_token_span').innerHTML = timeInfo.long_term_token_span;
    }
    timingInfo();
    console.log(1001, 'Form loaded @ ' + js_utils.myTime());

    var removeBtnClicks = null;
    registerEvents();
    loadDataFromLocal();

    function registerEvents() {
        document.getElementById('add_param_btn').onclick = function () {
            add_param_line('.params_list');
        }
        document.getElementById('add_header_btn').onclick = function () {
            add_param_line('.headers_list');
        }

        removeBtnClicks = function(){
            document.querySelectorAll('.remove_param_btn').forEach(function (el) {
                if(el.onclick) return;
                el.onclick = function () {
                    if (el.parentNode.children.length > 1) {
                        el.parentNode.remove();
                    } else {
                        el.style.display = 'none';
                    }
                }
            });
        }
        removeBtnClicks();

        config_params.forEach(function (config_item) {
            let drop_down = get_dd_input(config_item, 'select')
            drop_down.onchange = (ev) => { onDropDownChange(config_item, ev.target.value) };
        })

        document.querySelector('form').addEventListener('submit', function (ev) {
            ev.preventDefault();
            onSubmit();
        });

        function add_param_line(container_selector) {
            let source_el = document.querySelector(container_selector+' .param');
            let new_el = source_el.cloneNode(true);
            new_el.querySelector('input[name="name"]').setAttribute('value', '');
            new_el.querySelector('input[name="value"]').setAttribute('value', '');
            new_el.innerHTML += '<button type="button" class="remove_param_btn">Remove</button>';
            new_el.classList.remove('const_par');
            source_el.parentNode.appendChild(new_el);
            removeBtnClicks();
        }
    }

    function onDropDownChange(config_item, new_val) {
        js_utils.setLocalData(config_item+'_selected', new_val);
        get_dd_input(config_item, 'input').setAttribute('value', new_val);
    }    

    function get_dd_input(config_item, el_type='input'){
        let post_fix = el_type=='input' ? '_selected': '_list';
        return document.querySelector(el_type + '[name="' + config_item  + post_fix + '"]');
    }

    function onSubmit() {
        document.getElementById('error').innerHTML = '';
        config_params.forEach(config_item => {
            let el = get_dd_input(config_item, 'input');
            config_param_vals[config_item] = el.value;
        });

        let invalid_els = [];
        let input_data = {};
        document.querySelectorAll('.params_list .param').forEach(item => {
            let p_name_el = item.querySelector('input[name="name"]');
            if (p_name_el.value) {
                let pa_value_el = item.querySelector('input[name="value"]');
                if(!pa_value_el.value){
                    invalid_els.push(pa_value_el)
                } else {
                    pa_value_el.removeAttribute('is_empty');
                }
                input_data[p_name_el.value] = pa_value_el.value;
            }
        })

        let req_headers = {};
        document.querySelectorAll('.headers_list .param').forEach(item => {
            let p_name_el = item.querySelector('input[name="name"]');
            if (p_name_el.value) {
                let pa_value_el = item.querySelector('input[name="value"]');
                if(!pa_value_el.value){
                    invalid_els.push(pa_value_el)
                } else {
                    pa_value_el.removeAttribute('is_empty');
                }
                req_headers[p_name_el.value] = pa_value_el.value;
            }
        })

        if(invalid_els.length){
            invalid_els.forEach(item=>{
                item.setAttribute('is_empty', '1')
            });
            document.getElementById('error').innerHTML = 'Please fill read boxes';
            invalid_els[0].focus();
            return;
        }

        var req_data = {
            method: 'POST',
            headers: req_headers,
            body: JSON.stringify(input_data)
        };
        var token_refreshing = 0;
        do_api_request(config_param_vals.url, req_data);
    }

    function onRefreshTokenUpdated(new_token){
        let timeInfo = js_utils.getLocalData('time_info');
        timeInfo.long_token_time = new Date();
        js_utils.setLocalData('time_info', timeInfo);
        document.querySelector('.value.long_token_time').innerHTML = js_utils.myTime(timeInfo.long_token);
    }

    function onAccessTokenUpdated(new_token){
        let token_el = document.querySelector('.param input[value="Authorization"]');
        document.querySelector('input.token').setAttribute('value', '');
        let timeInfo = js_utils.getLocalData('time_info');
        timeInfo.short_token_time = new Date();
        js_utils.setLocalData('time_info', timeInfo);
        document.querySelector('.value.short_token_time').innerHTML = js_utils.myTime(timeInfo.short_token);
        document.querySelector('input.token').setAttribute('value', new_token);
        js_utils.setLocalData('token', new_token);
    }

    function getErrorFromJsonData(json_data, route){
        if(json_data.error){
            onApiError(json_data.error, route);
            return true;
        }
        if(json_data.result && json_data.result.error){
            onApiError(json_data.result.error, route);
            return true;
        }
    }

    async function do_api_request(req_url, fetch_params, call_backs={}) {
    	try {
    		let host_url = js_utils.getLocalData('host');
    		let server_end_point_url = host_url + req_url;
    		const response = await fetch(server_end_point_url, fetch_params);
    		let savedRequest = {
    		    route: req_url,
    		    request_data: fetch_params,
    		    call_backs: call_backs
    		}
    		if (response.status === 401) {
    			renewAccessTokenAndResendRequests(savedRequest);
    			return;
    		}
    		if (!response.ok) {
    			console.log(32131318, js_utils.myTime(), response.status, req_url);
    			onApiFailed({status: response.status, message:  `Request failed: ${response.statusText}`}, req_url);
    			return;
    		}
    		const json_data = await response.json();
    		try{
    		    let err_message = json_data.error.data.message;
    		    console.log(32131318, js_utils.myTime(), json_data.error.data, req_url);
                if(err_message.startsWith('401 Unauthorized')){
                    renewAccessTokenAndResendRequests(savedRequest);
                    return;
                }
            } catch (err){
            }
            console.log(32131318, js_utils.myTime(), json_data.result, req_url);

    		storeDataToLocal();

    		if(getErrorFromJsonData(json_data, req_url)) return;
    		let extracted_data = json_data.result;
    		if (extracted_data.access_token) {
    			onAccessTokenUpdated(extracted_data.access_token);
    		} else if(extracted_data.refreshToken){
    		    onRefreshTokenUpdated(extracted_data.refreshToken);
    		}
    		if(extracted_data.logged_out){
    		    js_utils.setLocalData('token', '');
    		    js_utils.setLocalData('user_id', '');
    		    window.location = '/api/login';
    		}
    		if (call_backs.onSuccess) {
    			call_backs.onSuccess(extracted_data.result);
    		}
    		document.getElementById('error').innerHTML = js_utils.myTime() + ', success for ' + req_url;
    	} catch (error) {
    		onApiDataError(error, req_url);
    	}
    }

    async function renewAccessTokenAndResendRequests(savedRequest) {
    	let host_url = js_utils.getLocalData('host');
    	let api_route = host_url + '/api/update/access-token/';
    	let server_route = host_url + '/api/update/access-token/';
    	try {
    		let fetch_params = savedRequest.request_data
    		savedRequest.request_data.headers['Authorization'] = savedRequest.request_data.headers.refreshToken || '';
    		const response = await fetch(server_route, fetch_params);
    		if (!response.ok) {
    			onApiFailed({status: response.status, message:  `Request failed: ${response.statusText}`}, api_route);
    			return;
    		}

    		const json_data = await response.json();
    		if (getErrorFromJsonData(json_data, api_route)) return;
    		let extracted_data = json_data.result;
    		onAccessTokenUpdated(extracted_data.access_token);
    		savedRequest.request_data.headers['Authorization'] = extracted_data.access_token;
    		do_api_request(savedRequest.route, savedRequest.request_data, savedRequest.callbacks);
    	} catch (error) {
    		onApiDataError(error, api_route)
    	}
    }

    function onApiError(err, route) {
        console.log(22022, 'Error in api response', err);
        if (err.data) {
            err = err.data;
            err = err.name + ' => ' + err.message;
        } else if (err.error) {
            err = err.error;
        } else if (err.message) {
            err = err.message;
        }
        document.getElementById('error').innerHTML = js_utils.myTime() + ', Error => ' + err;
    }

    function onApiDataError(err, route) {
        console.log(33033, 'Api data error', err)
        document.getElementById('error').innerHTML = 'Error in processing api data: '+ err;
    }

    function onApiFailed(err, route) {
        console.log(11011, 'Api Failed', err);
        document.getElementById('error').innerHTML = 'Status: '+err.status + ', Error => ' + err.message;
    }

    function loadDataFromLocal() {
        let localData = js_utils.getLocalData('all_data');
        if(!Object.keys(localData).length){
            window.location = '/api/login';
            return;
        }
        config_params.forEach(function (config_item) {
            let drop_down = get_dd_input(config_item, 'select');
            let input = get_dd_input(config_item, 'input');
            let data_list = js_utils.getLocalData(config_item + '_list') || [];
            if (data_list.length) {
                let new_nodes_str = '';
                data_list.forEach(option_val => {
                    new_nodes_str += `<option>${option_val}</option>`;
                })
                drop_down.innerHTML = new_nodes_str;
            }
            let config_item_value = js_utils.getLocalData(config_item + '_selected');
            if (config_item_value) {
                let ii = 0;
                let selectedIndex = -1;
                for( let dd_item of drop_down.children){
                    if(dd_item.value == config_item_value){
                        selectedIndex = ii;
                    }
                    ii++;
                }
                if(selectedIndex > -1){
                    drop_down.selectedIndex = selectedIndex;
                }
                get_dd_input(config_item, 'input').setAttribute('value', config_item_value);
            } else if (data_list.length) {
                input.setAttribute('value', data_list[0]);
            } else {
                input.setAttribute('value', drop_down.value || '');
            }
        });

        //console.log(423456, localData);

        load_input_header_params('.headers_list', 'headers');
        load_input_header_params('.params_list', 'params');

        document.querySelector('.params_list .user_id').setAttribute('value', js_utils.getLocalData('user_id') || '');
        document.querySelector('.headers_list .token').setAttribute('value', js_utils.getLocalData('token') || '');

        function load_input_header_params(container_selector, params_type) {
            var params_ar = js_utils.getLocalData(js_utils.addTrailingSlash(api_url) + params_type) || [];
            let params_container = document.querySelector(container_selector);
            if(!params_container){
                throw('Invalid params_container for => ', container_selector);
            }

            let new_nodes_str = '';
            params_ar.forEach(item => {
                let param_div = params_container.querySelector('.param:not(.const_par input[name="name"][value="'+item.name+'"]');
                if(param_div) {
                    param_div = param_div.parentNode;
                    if(item.value) {
                        param_div.querySelector('input[name="value"]').setAttribute('value', item.value);
                    }
                } else{
                    new_nodes_str += `
                    <div class="param" name="${item.name}">
                        <label>Name</label>
                        <input name="name" value="${item.name}" />
                        <label>Value</label>
                        <input name="value" value="${item.value}" />
                        <button type="button" class="remove_param_btn">Remove</button>
                    </div>
                    `;
                }
            })
            params_container.innerHTML += new_nodes_str;
            removeBtnClicks();
        }
    }

    function storeDataToLocal() {
        config_params.forEach(function (config_item) {
            let config_el = get_dd_input(config_item, 'input');
            let drop_down = get_dd_input(config_item, 'select');

            let found = 0;
            let data_list = [];
            let drop_down_items = [];
            js_utils.setLocalData(config_item + '_selected', config_el.value);
            for(let dd_item of drop_down.children){
                data_list.push(dd_item.value);
                if(dd_item.value == config_el.value){
                    found = 1;
                }
            }
            if(!found){
                drop_down.innerHTML += '<option>'+config_el.value+'</option>';
                data_list = [config_el.value].concat(data_list);
            }
            js_utils.setLocalData(config_item + '_list', data_list);
        });

        store_params('.params_list', 'params');
        store_params('.headers_list', 'headers');

        function store_params(container_selector, params_type) {
            let params_ar = [];
            document.querySelectorAll(container_selector + ' .param:not(.const_par)').forEach(param_div => {
                let p_name = param_div.querySelector('input[name="name"').value;
                if (p_name) {
                    params_ar.push({ name: p_name, value: param_div.querySelector('input[name="value"').value });
                }
            });
            js_utils.setLocalData(js_utils.addTrailingSlash(api_url) + params_type, params_ar);
        }
    }
})();
