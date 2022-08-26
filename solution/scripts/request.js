Java.perform(function() {
    let PasswordUtils = Java.use('org.mothra.smiley_day.PasswordUtils');
    let JavaString = Java.use('java.lang.String');

    for(let i = 1; i <= 3; i++) {
        let javaString = JavaString.$new("test" + "a".repeat(i));
        console.log(PasswordUtils.getEncryptedPasswordsFromCloud.call(PasswordUtils, javaString));
        console.log(PasswordUtils.getEncryptedPasswordsFromCloud.call(PasswordUtils, javaString));
    }
});
