 var myProxy =  (req, res, next)=>{
    console.log("myProxy is working.........")
    
    next()
}


module.exports = myProxy;