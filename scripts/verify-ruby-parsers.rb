# Development-only independent replay. Run with the reference repository's bundle.
require 'bundler/setup'
require 'json'
require 'digest'
require 'vxlan'
root = File.expand_path(ARGV.fetch(0))
reference = File.expand_path(ARGV.fetch(1, Dir.pwd))
manifest = JSON.parse(File.read(File.join(root, 'docs/ruby-baseline.json')))
manifest.fetch('files').each do |name, digest|
  abort "Ruby baseline drift: #{name}" unless Digest::SHA256.file(File.join(reference, name)).hexdigest == digest
end
count = 0
configuration = Vxlan::Config.new
runtime = Vxlan::RuntimeParser.new
rows = Dir[File.join(root, 'testdata/configuration/*.json')].sort.map { |file| JSON.parse(File.read(file)) }
Dir[File.join(root, 'testdata/runtime/*.json')].sort.each { |file| rows.concat(JSON.parse(File.read(file))) }
rows.each do |row|
  result = if row.fetch('name') == 'configuration'
    configuration.parse(row.fetch('text'), complete: row.fetch('complete'))
  else
    runtime.parse(row.fetch('name').to_sym, row.fetch('text'), complete: row.fetch('complete'))
  end
  expected = row.fetch('expected')
  actual = JSON.parse(JSON.generate(result.to_h)).slice(*expected.keys)
  abort "Parser drift at #{row['id'] || count}" unless actual == expected
  count += 1
end
puts "PASS: #{manifest.fetch('files').size} baseline hashes and #{count} Ruby parser observations"
