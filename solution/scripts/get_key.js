Java.perform(function (){
    let NothingToSeeHereActivity = Java.use("org.mothra.smiley_day.NothingToSeeHereActivity");
    NothingToSeeHereActivity.n0.implementation = function(){
        console.log('n0 is called');
        let ret = this.n0();
        console.log('n0 ret value is ' + ret);
        return ret;
    };
});