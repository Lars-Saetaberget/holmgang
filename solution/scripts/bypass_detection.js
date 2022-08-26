Java.perform(
    function (){
        let ValidatePasswordActivity = Java.use("org.mothra.smiley_day.ValidatePasswordActivity");
        ValidatePasswordActivity.l0.implementation = function(){
            console.log('Bypassing cop detection!');
            return false;
        };
    });