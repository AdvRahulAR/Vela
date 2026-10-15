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

/** Common surnames; used to extend a lowercase first-name match ("rahul sharma") by one word. */
const SURNAMES = `
sharma verma gupta singh kumar patel reddy nair menon iyer iyengar rao khan shah mehta jain agarwal agrawal mishra pillai
das bose banerjee chatterjee mukherjee desai joshi kulkarni naidu pandey saxena srivastava tiwari yadav chauhan malhotra
kapoor bhatt sinha dutta ghosh sen roy mathew thomas varghese kurian fernandes dsouza d'souza pinto nambiar kurup
warrier panicker chandran krishnan raman nathan subramanian venkatesan rajan ravi babu prasad murthy acharya hegde
shetty kamath pai bhat gowda naik deshpande deshmukh patil jadhav pawar shinde kale more wagh bhosale chavan gaikwad
sawant naidu chowdhury choudhary chaudhary chowdary bhattacharya bhattacharjee ganguly sarkar majumdar basu mitra dey
paul biswas mondal ahmed ahmad hussain husain siddiqui ansari sheikh shaikh qureshi syed mirza malik kaur gill sandhu
sidhu dhillon grewal bajwa brar sethi khanna chopra arora bhatia tandon mehra sood grover bedi anand bansal goyal
mittal singhal garg aggarwal jindal khandelwal maheshwari soni rathod rathore solanki parmar panchal thakur thakkar
modi trivedi dave pandya vyas raval mahajan khurana nanda bhargava tripathi dubey dwivedi upadhyay shukla chaturvedi
dixit awasthi vajpayee pathak sahu sahoo mohanty panda nayak behera swain lenka pradhan dash samal senapati
smith johnson williams brown jones miller davis garcia rodriguez wilson martinez anderson taylor thomas hernandez
moore martin jackson thompson white lopez lee gonzalez harris clark lewis robinson walker perez hall young allen
sanchez wright king scott green baker adams nelson hill ramirez campbell mitchell roberts carter phillips evans
turner torres parker collins edwards stewart flores morris nguyen murphy rivera cook rogers morgan peterson cooper
reed bailey bell gomez kelly howard ward cox diaz richardson wood watson brooks bennett gray james reyes cruz hughes
price myers long foster sanders ross morales powell sullivan russell ortiz jenkins gutierrez perry butler barnes
fisher henderson coleman simmons patterson jordan reynolds hamilton graham kim wallace west cole stone hawkins
dunn perkins hudson spencer gardner stephens payne pierce berry matthews arnold wagner willis ray watkins olson
carroll duncan snyder hart cunningham bradley lane andrews ruiz harper fox riley armstrong carpenter weaver greene
lawrence elliott chavez sims austin peters kelley franklin lawson fields ryan schmidt carr vasquez castillo
wheeler chapman oliver montgomery richards williamson johnston banks meyer bishop mccoy howell alvarez morrison
hansen fernandez garza harvey little burton stanley nguyen george jacobs reid kim fuller lynch dean gilbert garrett
romero welch larson frazier burke hanson day mendoza moreno bowman medina fowler brewer hoffman carlson silva
pearson holland douglas fleming jensen vargas byrd davidson hopkins may terry herrera wade soto walters curtis
neal caldwell lowe jennings barnett graves jimenez horton shelton barrett obrien castro sutton gregory mckinney
lucas miles craig rodriquez chambers holt lambert fletcher watts bates hale rhodes pena beck newman haynes mcdaniel
mendez bush vaughn parks dawson santiago norris hardy love steele curry powers schultz barker guzman page munoz ball
keller chandler weber leonard walsh lyons ramsey wolfe schneider mullins benson sharp bowen daniel barber cummings
hines baldwin griffith valdez hubbard salazar reeves warner stevenson burgess santos tate cross garner mann mack
moss thornton dennis mcgee farmer delgado aguilar vega glover manning cohen harmon rodgers robbins newton todd
blair higgins ingram reese cannon strickland townsend potter goodwin walton rowe hampton ortega patton swanson
joseph francis goodman maldonado yates becker erickson hodges rios conner adkins webster norman malone hammond
flowers cobb moody quinn blake maxwell pope floyd osborne paul mccarthy guerrero lindsey estrada sandoval gibbs
tyler gross fitzgerald stokes doyle sherman saunders wise colon gill alvarado greer padilla simon waters nunez
ballard schwartz mcbride houston christensen klein pratt briggs parsons mclaughlin zimmerman french buchanan moran
copeland roy pittman brady mccormick holloway brock poole frank logan owen bass marsh drake wong jefferson park
morton abbott sparks patrick norton huff clayton massey lloyd figueroa carson bowers roberson barton tran lamb
harrington casey boone cortez clarke mathis singleton wilkins cain bryan underwood hogan mckenzie collier luna
phelps mcguire allison bridges wilkerson nash summers atkins wang li zhang liu chen yang huang zhao wu zhou xu sun ma
zhu hu guo he gao lin luo zheng tanaka suzuki sato takahashi watanabe ito yamamoto nakamura kobayashi kato
`;

/**
 * First names and surnames that are also ordinary English / Hinglish words —
 * only matched with a surname, a strong cue, or capitalisation; never matched
 * as a bare lowercase word.
 */
const AMBIGUOUS = new Set(
  `will grace mark may rose hope joy faith bill amber summer chase pat sunny art rich dawn eve holly iris ivy june lily
ruby violet april august frank gene guy jean ray rob sandy sky star cliff drew earl glen lee miles ward wade penny king
prince major hunter mason carter cooper taylor ram harsh christian
brown white young green hill wood stone bell price long short little small day knight bishop page fox wolf bird field
ford marsh moore wright cook reed cox jain shah khan das bose more pai dash love cross mann moss bush parks powers
sharp daniel wise simon waters french park sun ma he lin cain nash`.split(/\s+/).filter(Boolean),
);

/**
 * Names that are ordinary words only when written in lowercase (Hinglish nouns
 * such as "vikas" = development, "deepak" = lamp; English words such as
 * "carol", "heather"). Capitalised, they are still treated as names.
 */
const LOWERCASE_AMBIGUOUS = new Set(
  `carol heather jordan austin madison virginia victoria wang yang ming zara sakura kamal kiran vikas vijay anand akash
sagar bharat asha prakash uday suman deepak amar nitya diya pari tara alice prem shanti mohan gopal shiv krishna ganesh
lakshmi priya jaya vidya usha uma meena sona pooja puja kavita geeta gita sudha madhu rani raja kumar kumari`
    .split(/\s+/)
    .filter(Boolean),
);

const FIRST = new Set(FIRST_NAMES.split(/\s+/).filter(Boolean));
const SURNAME = new Set(SURNAMES.split(/\s+/).filter(Boolean));

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

/** True when a bare lowercase `word` is too likely to be an ordinary word to be treated as a name. */
export function isLowercaseAmbiguous(word: string): boolean {
  const w = word.toLowerCase();
  return AMBIGUOUS.has(w) || LOWERCASE_AMBIGUOUS.has(w);
}

export function isKnownSurname(word: string): boolean {
  return SURNAME.has(word.toLowerCase());
}

/**
 * Normalised name components of a person-name span: words of 3+ letters that
 * are not stopwords, lower-cased, with trailing "." / "'s" stripped.
 */
export function personComponents(value: string): string[] {
  const out: string[] = [];
  for (const raw of value.split(/[\s,]+/)) {
    const w = raw.replace(/\.$/, '').replace(/['’]s$/i, '');
    if (w.length >= 3 && !isNameStopword(w) && /^[A-Za-z][A-Za-z'’-]+$/.test(w)) out.push(w.toLowerCase());
  }
  return out;
}

export function isNameStopword(word: string): boolean {
  return NAME_STOPWORDS.has(word.toLowerCase().replace(/[.,]$/, ''));
}
