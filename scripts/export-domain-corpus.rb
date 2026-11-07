# Development oracle: run Ruby specs with -r this file; never loaded by Go.
require 'vxlan'
require 'vxlan/fabric/review'
require 'vxlan/prefix_list_references'
require 'json'
require 'digest'
module DomainCorpus
  def self.capture(name, input)
    return yield if Thread.current[:skip_domain_corpus]
    input = JSON.parse(JSON.generate(input))
    begin
      result = yield
      expected = result.respond_to?(:to_h) && !result.nil? && !result.is_a?(Array) ? result.to_h : result
      record(name, input, JSON.parse(JSON.generate(expected)), nil)
      result
    rescue StandardError => e
      record(name, input, nil, e.class.name)
      raise
    end
  end
  def self.record(name, input, expected, error)
    return if Thread.current[:skip_domain_corpus]
    row = { name: name, input: input, expected: expected, error: error }
    key = Digest::SHA256.hexdigest(JSON.generate(row))
    File.write(File.join(ENV.fetch('VXLAN_DOMAIN_DIR'), key + '.json'), JSON.generate(row) + "\n")
  end
end
module DomainAdvice
  def call = DomainCorpus.capture('recommendations', document: @document) { super }
end
module DomainFabric
  def call = DomainCorpus.capture('fabric', documents: @documents.values, policy: { fabrics: @scope.groups }) { super }
end
module DomainPlans
  def build(change)
    plan = nil
    DomainCorpus.capture('build', change: change) do
      plan = super
      { change: plan.to_h, commands: plan.commands, rollback: plan.rollback }
    end
    plan
  end
  def fingerprint(value) = DomainCorpus.capture('fingerprint', value: value) { super }
end
module DomainPlanState
  def eligible?(config) = DomainCorpus.capture('eligible', change: to_h, config: config) { super }
  def satisfied?(after, before:) = DomainCorpus.capture('satisfied', change: to_h, after: after, before: before) { super }
end
module DomainPolicy
  def rules(entries) = DomainCorpus.capture('acl_rules', entries: entries) { super }
  def resolve(config, entries) = DomainCorpus.capture('acl_policy', config: config, entries: entries) { super }
end
module DomainPrefix
  def call(address_family: 'ipv4') = DomainCorpus.capture('prefix_references', config: @configuration, family: address_family) { super }
end
module DomainCombine
  def combine(local, supplemental) = DomainCorpus.capture('combine', advice: local, additions: supplemental) { super }
end
Vxlan::Recommendations.prepend(DomainAdvice)
Vxlan::Recommendations.singleton_class.prepend(DomainCombine)
Vxlan::Fabric::Review.prepend(DomainFabric)
Vxlan::ChangePlan.singleton_class.prepend(DomainPlans)
Vxlan::ChangePlan.prepend(DomainPlanState)
Vxlan::AclPolicy.singleton_class.prepend(DomainPolicy)
Vxlan::PrefixListReferences.prepend(DomainPrefix)
# Golden capture must not affect the original allocation-growth assertion.
require 'rspec/core'
RSpec.configure do |config|
  config.around do |example|
    Thread.current[:skip_domain_corpus] = example.description.include?('allocation growth')
    example.run
  ensure
    Thread.current[:skip_domain_corpus] = false
  end
end

module DomainCatalog
  def services = DomainCorpus.capture('catalog', configs: @configs) { super }
end
module DomainCatalogHelpers
  def route_targets(entries, asn:, vni:) = DomainCorpus.capture('route_targets', entries: entries, asn: asn, vni: vni) { super }
end
module DomainScope
  def initialize(policy)
    DomainCorpus.capture('scope', policy: policy) { super; groups }
  end
end
module DomainSubnet
  def initialize(config)
    @domain_config = JSON.parse(JSON.generate(config))
    super
  end
  def conflicts(address:, vrf:, vni:, except_interface: nil)
    DomainCorpus.capture('subnets', config: @domain_config, address: address, vrf: vrf, vni: vni, except_interface: except_interface) { super }
  end
end
Vxlan::Service::Catalog.prepend(DomainCatalog)
Vxlan::Service::Catalog.singleton_class.prepend(DomainCatalogHelpers)
Vxlan::Fabric::Scope.prepend(DomainScope)
Vxlan::SubnetIndex.prepend(DomainSubnet)
