using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SoftSwitch.components
{
    public class RuleAclDisplay
    {
        public bool IsEnabled { get; set; }
        public string Description { get; set; }
        public List<RuleAcl> Rules { get; set; } 
        public RuleAclDisplay(List<RuleAcl> rules)
        {
            Rules = rules;
            IsEnabled = rules.All(r => r.IsEnabled);             
            Description = GenerateDescription();
        }

        private string GenerateDescription()
        {
            if (Rules.Count == 1)
                return Rules[0].Description;

            if (Rules.All(r => r.Protocol == ProtocolType.ICMP))
            {
                var denyRule = Rules.FirstOrDefault(r => r.Action == AclAction.Deny);
                if (denyRule != null)
                    return denyRule.Description;                 
                return Rules[0].Description;             
            }

            if (Rules.All(r => r.Action == AclAction.Permit && r.Protocol == ProtocolType.Any))
            {
                string source = Rules[0].Description.Split(new[] { "from" }, StringSplitOptions.None)[1].Split('(')[0].Trim();
                return $"Permit Any from {source} (In/Out)";
            }

            return Rules[0].Description;         
        }
    }
}
