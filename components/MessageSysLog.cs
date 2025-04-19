

namespace SoftSwitch.components
{
    public enum Facility
    {
        HARDWARE,
        ACL,
        MAC, 
        SYS
    }
    public enum Severity
    {
        Critical = 2,   
        Error = 3,      
        Warning = 4,    
        Informational = 6 
    }
    public enum Mnemonic
    {
        PORT_DIS,
        ACL_DROP,
        PKT_SENT, 
        PORT_MOVE
    }
    public class MessageSysLog
    {
        public int PRI { get; private set; }
        public DateTime DateTime { get; set; }
        public Facility Facility { get; set;}
        public Severity Severity { get; set;}
        public Mnemonic Mnemonic { get; set;}
        public string Description { get; set;}  
        public MessageSysLog(DateTime _DateTime, Facility facility, Severity severity, Mnemonic mnemonic, string description)
        {
           
            DateTime = _DateTime;   
            Facility = facility;
            Severity = severity;
            Mnemonic = mnemonic;
            Description = description;
            PRI = ((int)facility * 8) + (int)severity;

        }
        public override string ToString()
        {
            return $"<{PRI}> {DateTime:MM/dd HH:mm:ss} {Facility} {Severity} {Mnemonic}: {Description}";
        }

    }
}
