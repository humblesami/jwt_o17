(function(){
    let ls_prefix = 'odoo_17_jwt';
    let form = document.getElementById('form');
    form.elements[0].focus();
    console.log(63893, form);
    document.getElementById('host_url').value = '' + window.location.origin;
    function onApiError(err){
        if(err.data){
            err = err.data;
            err  = err.name +' => ' +err.message;
        } else if(err.error){
             err = err.error;
        } else if(err.message){
             err = err.message;
        }
        document.getElementById('error').innerHTML = Date() + ', Error => ' + err;
    }

    function setLocalData(key, val){
        let prev_data = JSON.parse(localStorage.getItem(ls_prefix) || '{}');
        prev_data[key] = val;
        localStorage.setItem(ls_prefix, JSON.stringify(prev_data));
    }

    function onAuthenticated(data){
        if(data.error){
            onApiError(data.error);
            return;
        }
        let result = data.result;
        if(result.error){
            onApiError(result.error);
            return;
        }
        if(result && result.token){
            document.getElementById('error').innerHTML = '';
            setLocalData('token', result.token);
            setLocalData('user_id', result.user_id);
            let time_now = new Date();
            let time_info = {
                short_token_time: time_now,
                long_token_time: time_now,
                login_time: time_now,
                short_term_token_span: result.short_term_token_span,
                long_term_token_span: result.long_term_token_span,
            }
            setLocalData('time_info', time_info);
            let next_url = window.location.origin + '/api/template';
            console.log(next_url, result);
            window.location = next_url;
        } else {
            console.log('Invalid result', result);
        }
    }

    form.addEventListener('submit', function(ev){
        ev.preventDefault();
        let inputs = this.querySelectorAll('input');
        console.log(inputs);
        let input_data = {};
        inputs.forEach(function(el){
            let field_name = el.name;
            input_data[el.name] = el.value;
        });
        let host_url = document.getElementById('host_url').value.replace(/\/$/, "");
        setLocalData('host', host_url);
        let api_url = host_url + '/api/authenticate';
        console.log(api_url, input_data);
        document.getElementById('submit').setAttribute('disabled', 'disabled');

        function sendAuthRequest(){
            fetch(api_url, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(input_data)
            }).then((response) => {
                if(response.status != 200){
                    throw('Invalid request response '+response.status);
                }
               return response.json();
            }).then(function(data){
                try{
                    onAuthenticated(data);
                } catch (err){
                    onApiError('Error in onAuthenticated => ' + err);
                }
            }).catch(function(err){
                onApiError('' + err);
            }).finally(function(){
                document.getElementById('submit').removeAttribute('disabled');
            });
        }
        sendAuthRequest();
    });
})()