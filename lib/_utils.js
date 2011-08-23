// Returns true if this is a host that closes *before* it ends?!?!
module.exports.isAnEarlyCloseHost= function( hostName ) {
  return hostName.match(".*google(apis)?.com$")
}