function getCookie(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i].trim();
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

function setCookie(cname, cvalue, exdays) {
    var d = new Date();
    d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
    var expires = "expires=" + d.toGMTString();
    document.cookie = cname + "=" + cvalue + "; " + expires;
}

let auth = getCookie('auth');

function setAuth(newAuth) {
    setCookie('auth', newAuth);
    auth = newAuth
}


function getRootPath() {
    return window.location.protocol + '//' + window.location.host + '/'
}

function getUrl(url) {
    return getRootPath() + url
}

function post(url, data, success, error,) {
    $.ajax({
        url: getUrl(url),
        type: 'post',
        dataType: 'json',
        headers: {
            'content-Type': "application/json",
            'Authorization': 'Bearer ' + auth
        },
        data: JSON.stringify(data),
        success: function (response) {
            console.log(response)
            if (response && response.code === 401) {
                setAuth(null);
                window.location.replace("login.html");
                return;
            }
            if (success) {
                success(response)
            }
        },
        error: function (e) {
            console.log(e)
            if (error) {
                error(e)
            }
        }
    });
}

function postLogin(requestData, success, error) {
    post("login", requestData, success, error)
}

function postGroupList(requestData, success, error) {
    post("group_list", requestData, success, error)
}

function postGroupInfo(requestData, success, error) {
    post("group_info", requestData, success, error)
}
