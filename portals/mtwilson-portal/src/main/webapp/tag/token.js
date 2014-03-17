/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

// cross-site request forgery protection
var authorizationToken = null;
function setTokenInAllForms(token) {
    $$("form[method=POST]").each(function(){ 
        var form = $(this);
        // check if there is already an AuthorizationToken hidden input if we have a newer token we should replace it
        var inputs = form.select("input[type=hidden][name=AuthorizationToken]");
        if( inputs.length ) {
            // form already includes an AuthorizationToken field, so replace its value
            inputs.each(function() {
                var tokenInput = $(this);
                tokenInput.value = token;
            });
        }
        else {
            // form does not already include an AuthorizationToken field, so add it 
            form.insert({top: new Element("input", {name:"AuthorizationToken",type:"hidden",value:token})});
        }
    });
}
function setTokenInHttpEquiv(token) {
    var meta = $$("meta[http-equiv=AuthorizationToken]");
    if( meta.length ) {
        meta.each(function() {
            $(this).value = token;
        });
    }
    else {
        $$("head")[0].insert({top: new Element("meta", { "http-equiv":"AuthorizationToken", value:token })});
    }
}
function getAuthorizationToken() {
    // XXX TODO look for expiration header with token and set a timer; if token has expired get a new one, otherwise use existing token
    // first look for an authorization token embedded in the current page
    var meta = $$("meta[http-equiv=AuthorizationToken]");
    if( meta.length ) {
        authorizationToken = meta[0].value;
        //alert("got token from meta: "+authorizationToken);
        setTokenInAllForms(authorizationToken);
        return;
    }
    // if we didn't find it in the meta tags then make an ajax request to get a new token
	// TODO:
	/*
    $.ajax({
        type: "GET",
        url: "AuthorizationToken.jsp",
        success: function(data, status, xhr) {
            authorizationToken = xhr.getResponseHeader("AuthorizationToken");
            //alert("got token from ajax: "+authorizationToken);
            setTokenInAllForms(authorizationToken);
            setTokenInHttpEquiv(authorizationToken);
        }
    });
	*/
}

