# Development-only source oracle; the Go product never invokes Ruby.
# Run with the reference vxlan repository's bundle and lib on the load path:
#   bundle exec ruby -Ilib /path/to/go-vxlan/scripts/export-source-corpus.rb /path/to/go-vxlan
require "bundler/setup"
require "json"
require "vxlan"
require "vxlan/cisco_nxos/parsers/show_running_config"

def source_blocks(roots)
  pending = roots.reverse.map { |block| [block, nil] }
  out = []
  until pending.empty?
    block, parent = pending.pop
    out << { first: block.line, last: block.line_range.end, parent: parent }
    pending.concat(block.children.reverse.map { |child| [child, block.line] })
  end
  out
end

root = File.expand_path(ARGV.fetch(0))
out = {}
Dir[File.join(root, "testdata/configuration/*.json")].sort.each do |file|
  fixture = JSON.parse(File.read(file))
  parser = Vxlan::CiscoNxos::Parsers::ShowRunningConfig.new
  begin
    parser.parse(fixture.fetch("text"), complete: fixture.fetch("complete"))
    out[File.basename(file)] = {
      states: parser.cursor.states,
      roots: source_blocks(parser.blocks),
      captures: parser.cursor.captures.map do |capture|
        { path: capture.path, data: capture.data, first: capture.block.line,
          last: capture.block.line_range.end, complete: capture.complete? }
      end
    }
  rescue ArgumentError => error
    out[File.basename(file)] = { error: error.message }
  end
end
File.write(ARGV[1] || File.join(root, "testdata/configuration_sources.json"), JSON.pretty_generate(out) + "\n")
