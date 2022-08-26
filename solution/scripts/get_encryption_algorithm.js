Java.perform(function() {
    let PasswordUtils = Java.use('org.mothra.smiley_day.PasswordUtils');
    console.log(PasswordUtils.getAlgorithm.call(PasswordUtils));
});

