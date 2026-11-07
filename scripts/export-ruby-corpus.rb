# Development-only oracle. Product runtime never loads Ruby.
require 'json'
require 'digest'
require 'fileutils'
require 'vxlan'
module VXLANCorpus
  def parse(*args, **kwargs)
    result = super
    text = args.last
    text = text.dup.force_encoding(Encoding::UTF_8) if text.is_a?(String)
    if text.is_a?(String) && text.valid_encoding?
      name = is_a?(Vxlan::Config) ? 'configuration' : args.first.to_s
      row = {name: name, text: text, complete: kwargs.fetch(:complete, false), expected: JSON.parse(JSON.generate(result.to_h))}
      row[:expected].delete('started_at'); row[:expected].delete('completed_at')
      key = Digest::SHA256.hexdigest(JSON.generate(row))
      path = File.join(ENV.fetch('VXLAN_CORPUS_DIR'), "#{key}.json")
      File.write(path, JSON.pretty_generate(row) + "\n")
    end
    result
  end
end
Vxlan::Config.prepend(VXLANCorpus)
Vxlan::RuntimeParser.prepend(VXLANCorpus)

module VXLANConfigCorpus
  def parse(text, **kwargs)
    result = super
    if text.is_a?(String) && text.dup.force_encoding(Encoding::UTF_8).valid_encoding?
      expected = JSON.parse(JSON.generate(result.to_h)).merge('name' => 'configuration', 'evidence' => [])
      row = {name: 'configuration', text: text.dup.force_encoding(Encoding::UTF_8), complete: kwargs.fetch(:complete, false), expected: expected}
      key = Digest::SHA256.hexdigest(JSON.generate(row))
      File.write(File.join(ENV.fetch('VXLAN_CORPUS_DIR'), "#{key}.json"), JSON.pretty_generate(row) + "\n")
    end
    result
  end
end
Vxlan::CiscoNxos::Parsers::ShowRunningConfig.prepend(VXLANConfigCorpus)
