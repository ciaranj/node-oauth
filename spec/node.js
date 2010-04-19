require.paths.unshift('spec', 'lib', 'spec/lib')
require("jspec")

print = require('sys').puts
quit = process.exit
readFile = require('fs').readFileSync

function run(specs) {
  specs.forEach(function(spec){
    JSpec.exec('spec/spec.' + spec + '.js')
  })
}

specs = {
  independant: [
    'oauth',
    'sha1'
    ]
}

switch (process.ARGV[2]) {
  case 'all':
    run(specs.independant)
    break
  default: 
    run([process.ARGV[2]])
}

JSpec.run({ reporter: JSpec.reporters.Terminal, failuresOnly: true }).report()