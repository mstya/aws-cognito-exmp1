using System.ComponentModel.DataAnnotations;

namespace AWSCongito.Models
{
    public class ConfirmAccountViewModel
    {
        [Required]
        [Display(Name = "Code")]
        public string Code { get; set; }
    }
}