EMPLOYEE_DESIGNATION = (
    ("CEO","CEO"),
    ("COO", "COO"),
    ("Project Manager", "Project Manager"),
    ("Jr. PHP Laravel Developer","Jr. PHP Laravel Developer"),
    ("Sr. Developer","Sr. Developer"),
    ("UI/UX Designer","UI/UX Designer"),
    ("Product Manager","Product Manager"),
    ("Quality Engineer","Quality Engineer"),
    ("Quality Engineer Lead","Quality Engineer Lead"),
    ("Web Designer","Web Designer"),
    ("Sr. Developer","Sr. Developer"),
    ("SEO Executive", "SEO Executive"),
    ("Jr. HR Executive", "Jr. HR Executive"),
    ("Jr. PHP Laravel Developer	", "Jr. PHP Laravel Developer"),
    ("Sr. HR Executive", "Sr. HR Executive"),
    ("Sr. SEO Executive", "	Sr. SEO Executive"),
    ("Content Writer", "Content Writer"),
    ("Python Developer", "Python Developer"),
    ("Jr. Web Designer", "Jr. Web Designer"),
    ("Intern", "Intern"),
    ("Lead Generation Executive", "Lead Generation Executive"),
    ("Trainee", "Trainee"),
)
EMPLOYEE_ROLE = (
    ("Admin", "Admin"),
    ("HR", "HR"),
    ("Employee", "Employee"),
)

EMPLOYEE_COMPANY = (
    ("PranshTech Solutions", "PranshTech Solutions"),
    ("Textdrip", "Textdrip"),
)

E_MENTOR=(
    ("Harsh Modi","Harsh Modi"),
    ("Kishan Patel","Kishan Patel"),
    ("Rahul Patel","Rahul Patel"),
    ("Harsh Sompura","Harsh Sompura"),
    ("Dhaval Gajjar","Dhaval Gajjar"),
    ("Vishal Tanna","Vishal Tanna"),
    ("Aakanksha Neliwer","Aakanksha Neliwer"),
    ("Bansari Goswami","Bansari Goswami"),
    ("Sandeep Makvana","Sandeep Makvana"),

)

E_PRIORITY=(
    ("Low","Low"),
    ("Medium","Medium"),
    ("High","High"),
    ("Urgent","Urgent"),
)

IN_OUT=(
    ("In","In"),
    ("Out","Out"),
)

APPROVEL_STATUS=(
    ("Accepted","Accepted"),
    ("Rejected","Rejected"),
    ("Pending","Pending")
)

ISSUE_STATUS =(
    ("Pending","Pending"),
    ("Solved","Solved")
)




EVENT_DAY = (
    ('Sunday', 'Sunday'),
    ('Monday', 'Monday'),
    ('Tuesday', 'Tuesday'),
    ('Wednesday', 'Wednesday'),
    ('Thursday', 'Thursday'),
    ('Friday', 'Friday'),
    ('Saturday', 'Saturday'),
)

LEAVE_TYPE = (
    ("Planned", "Planned"),
    ("Unplanned", "Unplanned"),
    ("Compensation", "Compensation")
)

LEAVE_DAY = (
    ("Full Day", "Full Day"),
    ("Half Day", "Half Day")
)

LEAVE_STATUS = (
    ("Pending", "Pending"),
    ("Approved", "Approved"),
    ("Rejected", "Rejected")
)

ALLOWANCE_TYPE = (
    ("Basic", "Basic"),
    ("Allowance", "Allowance"),
    ("Deduct", "Deduct")
)


AMOUNT_TYPE = (
    # ("Percentage", "Percentage"),
    ("Fixed", "Fixed"),
    ("Python Code", "Python Code")
)
class TableName:
    USERS = 'user'
    HOLIDAYS = 'holiday'
    LEAVES = 'leave'
    SALARY = 'salary'
    ALLOWANCE_PERCENTAGE_RULES = "allowance_percentage"
    SALARY_STRUCTURE = "salary_structure"
    EMPLOYEE_STATUS = "employee_status"
    EMP_CONTRACT = "emp_contract"
    RULES_CATEGORY = 'rules_category'
    RULES = "rules"
    EMPLOYEE_PAY_SLIP = "employee_pay_slip"
    COMPUTE_PAY_SLIP = "compute_pay_slip"

class Integers:
    HUNDRED = 100
    TWELVE = 12