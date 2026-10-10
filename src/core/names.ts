/**
 * Lightweight, dependency-free person-name heuristics.
 *
 * This is NOT a statistical NER model. It catches the common, high-signal cases
 * (honorifics, "my name is …", legal/role labels, sign-offs, a first-name
 * gazetteer and re-mentions of already-detected names). For higher recall plug a
 * real NER model in through `VelaConfig.recognizers`.
 */

const FIRST_NAMES = `
aarav aarti aarush aashish abdul abhay abhijit abhinav abhishek aditi aditya afsana afzal ahmed aisha ajay ajit akash akhil
akshay alok amar amit amita amitabh amol anand ananya anil anita anjali ankit ankita anoop anshul anuj anup anupam anuradha
anushka apoorva aravind archana arjun arpit arun aruna arvind asha ashok ashwin atul ayaan ayesha azhar balaji bharat bhavna
bhavya chetan chirag deepa deepak deepika devansh devendra dhruv dinesh divya farhan fatima gaurav geeta girish gopal gita
govind harish harsh harsha hemant himanshu hitesh imran irfan ishaan ishita jagdish jaya jayant jitendra jyoti kabir kajal
kamal kamala karan karthik kavita kavya kiran kishore krishna kunal lakshmi lalit madhav madhu mahesh manish manisha manoj
meena meera mohan mohit monika mukesh murali nagesh naresh naveen neha nikhil nisha nitin nitya pallavi pankaj parth pooja
pradeep prakash pranav prashant pratik praveen preeti prem priya priyanka puja rahul raj rajat rajesh rajiv rakesh ram ramesh
rani ravi rekha reshma riya rohan rohit rupal sachin sagar sahil sajid salman sameer sandeep sangeeta sanjay sanjana santosh
sarita satish saurabh seema shalini shankar sharad shikha shilpa shiv shivani shreya shruti shweta siddharth simran sneha
sonal sonia sridhar srinivas subhash sudha sudhir suman sumit sunil sunita suraj suresh sushil swati tanvi tarun tushar uday
uma usha vaibhav varun vasudha venkat vibha vidya vijay vikas vikram vinay vineet vinod vipin vishal vivek yash yogesh zara
zoya arnav advait ishan reyansh vihaan aadhya diya saanvi myra kiara anvi navya pari riddhi tara mehul ritesh rupesh
gurpreet harpreet jaspreet manpreet simranjit baldev hardeep jasleen navjot amrita mamata sourav subrata debashish
anirban arijit soumya tanmoy suvendu rituparna madhuri ganesh senthil murugan karthikeyan saravanan lakshmanan
venkatesh ramya divyanka keerthi arul selvam thomas joseph mathew george john varghese jacob maria mary anthony
james robert michael william david richard charles christopher daniel matthew donald steven paul andrew joshua kenneth
kevin brian timothy ronald jason jeffrey ryan gary nicholas eric jonathan stephen larry justin scott brandon benjamin
samuel gregory alexander patrick dennis tyler aaron adam nathan henry zachary peter kyle noah ethan jeremy christian
sean austin jordan elijah lucas oliver liam logan emily emma olivia sophia isabella ava mia abigail madison elizabeth
sofia jennifer linda patricia barbara susan jessica sarah karen nancy betty margaret sandra ashley kimberly donna michelle
carol amanda melissa deborah stephanie rebecca laura sharon cynthia kathleen amy shirley angela helen anna brenda pamela
nicole samantha katherine christine rachel catherine carolyn janet virginia heather diane julie joyce victoria kelly
christina lauren evelyn judith megan cheryl andrea hannah jacqueline martha gloria teresa ann sara julia alice natalie
alan alex albert carlos jose juan luis miguel ahmad ali hassan hussain mohammed muhammad omar yusuf wei li ming hiroshi
yuki kenji sakura chen wang zhang liu yang alice bob carol dave alicia elena ivan dmitri olga sergei natasha
`;

/** First names that are also common English words — only matched with a surname or a strong cue. */
const AMBIGUOUS = new Set(
  `will grace mark may rose hope joy faith bill amber summer chase pat sunny art rich dawn eve holly iris ivy june lily
ruby violet april august frank gene guy jean ray rob sandy sky star cliff drew earl glen lee miles ward wade penny king
prince major hunter mason carter cooper taylor ram`.split(/\s+/).filter(Boolean),
);

const FIRST = new Set(FIRST_NAMES.split(/\s+/).filter(Boolean));

/** Words that can never be (part of) a detected name; trimmed from candidate edges. */
export const NAME_STOPWORDS = new Set(
  `mr mrs ms miss mx dr prof shri shree sri smt kumari kum adv advocate justice hon'ble honble sir madam late master
dear hi hello hey thanks thank regards sincerely best warm kind cheers yours truly respectfully
the a an this that these those my our your his her their its i we you he she they it me us them
and or but of in on at for from to with by as is was are were be been am not no yes if so then than
monday tuesday wednesday thursday friday saturday sunday january february march april june july august september
october november december jan feb mar apr jun jul aug sep sept oct nov dec today tomorrow yesterday
name client customer applicant petitioner respondent accused plaintiff defendant patient employee candidate beneficiary
nominee deponent complainant appellant tenant landlord borrower guarantor insured holder cardholder signed attn cc team
all user users colleagues friends everyone support sales hr admin manager director ceo cto cfo
mail email e-mail phone mobile tel address road street lane nagar marg colony sector block city state country
pan aadhaar gstin gst card account bank ifsc upi passport dob ssn iban api id no number
india indian ltd limited inc llp llc pvt private court high supreme district government ministry department
company corporation group project order invoice please kindly note subject re fwd urgent new old`.split(/\s+/).filter(Boolean),
);

/** Cues that, immediately preceding a capitalised span, mark it as a person name. */
export const STRONG_NAME_CONTEXT =
  /(?:\b(?:mr|mrs|ms|miss|mx|dr|prof|shri|shree|sri|smt|kumari|kum|adv|advocate|justice|hon'?ble|late)\.?|\bmy name is|\bmy name's|\bname\s*(?:is|:|-)|\bfull name\s*[:-]?|\bnamed|\bcalled|\bsigned(?: by)?\s*[:-]?|\b(?:client|applicant|petitioner|respondent|accused|plaintiff|defendant|customer|patient|employee|candidate|beneficiary|nominee|deponent|complainant|appellant|tenant|landlord|borrower|guarantor|insured|account holder|cardholder|holder)(?:'s)?\s*(?:name)?\s*[:-]?|\b[sdwc]\/o\.?|\b(?:son|daughter|wife|husband) of|\bdear|\bregards,?|\bsincerely,?|\bthanks,?|\battn\.?:?)\s*$/i;

export function isKnownFirstName(word: string): boolean {
  return FIRST.has(word.toLowerCase());
}

export function isAmbiguousName(word: string): boolean {
  return AMBIGUOUS.has(word.toLowerCase());
}

export function isNameStopword(word: string): boolean {
  return NAME_STOPWORDS.has(word.toLowerCase().replace(/[.,]$/, ''));
}
