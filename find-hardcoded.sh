#!/bin/bash

red="\e[31m"
green="\e[32m"
end="\e[0m"


#You can manually check this thing
#Authorization_Basic=$(grep -iRnE "basic [a-zA-Z0-9_\\-:\\.=]+")  or gf tool
#HTTPS_Protocol=$(grep -inRE "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*)")
#gf urls | grep "https://" | grep -iv "www.w3.org" | grep -iv "schemas.android.com" | sort -u
#HTTP_Protocol=$(grep -inRE "http?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*)" | grep -iv "schemas")
#gf urls | grep "http://" | grep -iv "www.w3.org" | grep -iv "schemas.android.com" | sort -u
#URL_Parameter=$(grep -inRE "(?<=\?|\&)[a-zA-Z0-9_]+(?=\=)") or we can use gf tool
#Artifactory_Password= $(grep -iRnE "(?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,}") or  grep -iRnP "basic [a-zA-Z0-9_\\-:\\.=]+" or using gf tool 
#Vault_Token=$(grep -iRnE "[sb]\\.[a-zA-Z0-9]{24}")
#Base32=$(grep -iRnE "(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?")
#ipv6=$(grep -inRE "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")



run_regex () {

red="\e[31m"
green="\e[32m"
end="\e[0m"



#ipv4-([0-9]{1,3}[\.]){3}[0-9]{1,3}

Slack_Token=$(grep -inRE "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})")
RSA_Private_Key=$(grep -inRE "BEGIN RSA PRIVATE KEY")
SSH_DSA_Private_Key=$(grep -inRE "BEGIN DSA PRIVATE KEY")
SSH_EC_Private_Key=$(grep -inRE "BEGIN EC PRIVATE KEY")
PGP_private_key_block=$(grep -inRE "BEGIN PGP PRIVATE KEY BLOCK")
AWS_Client_ID=$(grep -inRE "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
Base64=$(grep -inRE "(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+/]+={0,2}")
Authorization_Bearer=$(grep -inRE "bearer [a-zA-Z0-9_\\-\\.=]+")
Cloudinary_Basic_Auth=$(grep -inRE "cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+")
Google_Drive_API_Key=$(grep -inRE "AIza[0-9A-Za-z\\-_]{35}")
Google_Drive_Oauth=$(grep -inRE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")
Google_Gmail_API_Key=$(grep -inRE "AIza[0-9A-Za-z\\-_]{35}")
Google_Gmail_Oauth=$(grep -inRE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")
Google_Youtube_API_Key=$(grep -inRE "AIza[0-9A-Za-z\\-_]{35}")
Google_Youtube_Oauth=$(grep -inRE "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\\.com")
IPv4=$(grep -inRE "\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b")
Javascript_Variables=$(grep -inRE "(?:const|let|var)\s+\K(\w+?)(?=[;.=\s])")
LinkedIn_Client_ID=$(grep -inRE "(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]")
LinkedIn_Secret_Key=$(grep -inRE "(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]")
MD5_Hash=$(grep -inRE "[a-f0-9]{32}")
AWS_MWS_Key=$(grep -iRnE "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
Amazon_AWS_Access_Key_ID=$(grep -iRnE "([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}")
AWS_API_Key=$(grep -iRnE "AKIA[0-9A-Z]{16}")
Facebook_Access_Token=$(grep -iRnE "EAACEdEose0cBA[0-9A-Za-z]+")
Facebook_Secret_Key=$(grep -iRnE "(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}")
Facebook_OAuth=$(grep -iRnE "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]")
Facebook_ClientID=$(grep -iRnE "(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}")
Firebase=$(grep -iRnE "[a-z0-9.-]+\.firebaseio\.com")
GitHub=$(grep -iRnE "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]")
Generic_API_Key=$(grep -iRnE "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]")
Generic_Secret=$(grep -iRnE "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]")
Google_API_Key=$(grep -iRnE "AIza[0-9A-Za-z\\-_]{35}")
Google_Cloud_Platform_OAuth=$(grep -iRnE "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com")
Google_Cloud_Platform_Service_Account=$(grep -iRnE "\"type\": \"service_account\"")
Google_OAuth_Access_Token=$(grep -iRnE "ya29\\.[0-9A-Za-z\\-_]+")
Heroku_API_Key=$(grep -iRnE "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")
IP_Address=$(grep -iRnE "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])")
LinkFinder=$(grep -iRnE "(?:\"|')(((?:[a-zA-Z]{1,10}:\/\/|\/\/)[^\"'\/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:\/|\\.\\.\/|\\.\/)[^\"'><,;| *()(%%$^\/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-\/]{1,}\/[a-zA-Z0-9_\\-\/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-\/]{1,}\/[a-zA-Z0-9_\\-\/]{3,}(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\\?|#][^\"|']{0,}|)))(?:\"|')")
MailChimp_API_Key=$(grep -iRnE "[0-9a-f]{32}-us[0-9]{1,2}")
Mailgun_API_Key=$(grep -iRnE "key-[0-9a-zA-Z]{32}")
Password_in_URL=$(grep -iRnE "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]")
PayPal_Braintree_Access_Token=$(grep -iRnE 'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}')
Picatic_API_Key=$(grep -iRnE "sk_live_[0-9a-z]{32}")
Slack_Webhook=$(grep -iRnE "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}")
Stripe_API_Key=$(grep -iRnE "sk_live_[0-9a-zA-Z]{24}")
Stripe_Restricted_API_Key=$(grep -iRnE "rk_live_[0-9a-zA-Z]{24}")
Square_Access_Token=$(grep -iRnE "sq0atp-[0-9A-Za-z\\-_]{22}")
Square_OAuth_Secret=$(grep -iRnE "sq0csp-[0-9A-Za-z\\-_]{43}")
Twilio_API_Key=$(grep -iRnE "SK[0-9a-fA-F]{32}")
Twitter_ClientID=$(grep -iRnE "(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}")
Twitter_Access_Token=$(grep -iRnE "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}")
Twitter_Secret_Key=$(grep -iRnE "(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}")
Twitter_OAuth=$(grep -iRnE "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]")
Artifactory_API_Token=$(grep -iRnE "(?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}")
Basic_Auth_Credentials=$(grep -iRnE "(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z]+")
Cloudinary_Basic_Auth=$(grep -iRnE "cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+")
Mailto=$(grep -iRnE "(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+")
#Amazon_AWS_S3_Bucket
Amazon_AWS_S3_Bucket_1st=$(grep -iRnE "[a-z0-9.-]+\\.s3\\.amazonaws\\.com")
Amazon_AWS_S3_Bucket_2nd=$(grep -iRnE "[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com")
Amazon_AWS_S3_Bucket_3rd=$(grep -iRnE "[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)")
Amazon_AWS_S3_Bucket_4th=$(grep -iRnE "//s3\\.amazonaws\\.com/[a-z0-9._-]+")
Amazon_AWS_S3_Bucket_5th=$(grep -iRnE "//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+")
Amazon_AWS_S3_Bucket_6th=$(grep -iRnE "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

##########################################################################################################################################




[[ ! -z "$Slack_Token" ]] && echo -e $green"{~} Slack Token : " "$red$Slack_Token\n$end"
[[ ! -z "$RSA_Private_Key" ]] && echo -e $green"{~} RSA Private Key : " "$red$RSA_Private_Key\n$end"
[[ ! -z "$SSH_DSA_Private_Key" ]] && echo -e $green"{~} SSH DSA Private Key : " "$red$SSH_DSA_Private_Key\n$end"
[[ ! -z "$SSH_EC_Private_Key" ]] && echo -e $green"{~} SSH EC Private Key : " "$red$SSH_EC_Private_Key\n$end"
[[ ! -z "$PGP_private_key_block" ]] && echo -e $green"{~} PGP private key block : " "$red$PGP_private_key_block\n$end"
[[ ! -z "$AWS_Client_ID" ]] && echo -e $green"{~} AWS Client ID : " "$red$AWS_Client_ID\n$end"
[[ ! -z "$Base64" ]] && echo -e $green"{~} Base64 : " "$red$Base64$\n$end"
[[ ! -z "$Authorization_Bearer" ]] && echo -e $green"{~} Authorization Bearer : " "$red$Authorization_Bearer\n$end"
[[ ! -z "$Cloudinary_Basic_Auth" ]] && echo -e $green"{~} Cloudinary Basic Auth : " "$red$Cloudinary_Basic_Auth\n$end"
[[ ! -z "$Google_Drive_API_Key" ]] && echo -e $green"{~} Google Drive API Key : " "$red$Google_Drive_API_Key\n$end"
[[ ! -z "$Google_Drive_Oauth" ]] && echo -e $green"{~} Google Drive Oauth : " "$red$Google_Drive_Oauth\n$end"
[[ ! -z "$Google_Gmail_API_Key" ]] && echo -e $green"{~} Google Gmail API Key : " "$red$Google_Gmail_API_Key\n$end"
[[ ! -z "$Google_Gmail_Oauth" ]] && echo -e $green"{~} Google Gmail Oauth : " "$red$Google_Gmail_Oauth\n$end"
[[ ! -z "$Google_Youtube_API_Key" ]] && echo -e $green"{~} Google Youtube API Key : " "$red$Google_Youtube_API_Key\n$end"
[[ ! -z "$Google_Youtube_Oauth" ]] && echo -e $green"{~} Google Youtube Oauth : " "$red$Google_Youtube_Oauth\n$end"
[[ ! -z "$IPv4" ]] && echo -e $green"{~} IPv4 : " "$red$IPv4\n$end"
[[ ! -z "$Javascript_Variables" ]] && echo -e $green"{~} Javascript Variables : " "$red$Javascript_Variables\n$end"
[[ ! -z "$LinkedIn_Client_ID" ]] && echo -e $green"{~} LinkedIn Client ID : " "$red$LinkedIn_Client_ID\n$end"
[[ ! -z "$LinkedIn_Secret_Key" ]] && echo -e $green"{~} LinkedIn Secret Key : " "$red$LinkedIn_Secret_Key\n$end"
[[ ! -z "$MD5_Hash" ]] && echo -e $green"{~} MD5 Hash : " "$red$MD5_Hash\n$end"
[[ ! -z "$URL_Parameter" ]] && echo -e $green"{~} URL Parameter : " "$red$URL_Parameter\n$end"
[[ ! -z "$AWS_MWS_Key" ]] && echo -e $green"{~} AWS MWS Key : " "$red$AWS_MWS_Key\n$end"
[[ ! -z "$Amazon_AWS_Access_Key_ID" ]] && echo -e $green"{~} Amazon AWS Access Key-ID : " "$red$Amazon_AWS_Access_Key_ID\n$end"
[[ ! -z "$AWS_API_Key" ]] && echo -e $green"{~} AWS APIkey : " $green$AWS_API_Key\n$end
[[ ! -z "$Facebook_Access_Token" ]] && echo -e $green"{~} Facebook Access-Token : " "$red$Facebook_Access_Token\n$end"
[[ ! -z "$Facebook_Secret_Key" ]] && echo -e $green"{~} Facebook Secret-Key : " "$red$Facebook_Secret_Key\n$end"
[[ ! -z "$Facebook_OAuth" ]] && echo -e $green"{~} Facebook OAuth : " "$red$Facebook_OAuth\n$end"
[[ ! -z "$Facebook_ClientID" ]] && echo -e $green"{~} Facebook ClientID : " "$red$Facebook_ClientID\n$end"
[[ ! -z "$Firebase" ]] && echo -e $green"{~} Firebase : " "$red$Firebase\n$end"
[[ ! -z "$GitHub" ]] && echo -e $green"{~} GitHub : " "$red$GitHub\n$end"
[[ ! -z "$Generic_API_Key" ]] && echo -e $green"{~} Generic APIkey : " "$red$Generic_API_Key\n$end"
[[ ! -z "$Generic_Secret" ]] && echo -e $green"{~} Generic Secret : " "$red$Generic_Secret\n$end"
[[ ! -z "$Google_API_Key" ]] && echo -e $green"{~} Google APIkey : " "$red$Google_API_Key\n$end"
[[ ! -z "$Google_Cloud_Platform_OAuth" ]] && echo -e $green"{~} Google Cloud Platform-OAuth : " "$red$Google_Cloud_Platform_OAuth\n$end"
[[ ! -z "$Google_Cloud_Platform_Service_Account" ]] && echo -e $green"{~} GoogleCloud Platform Service Account : " "$red$Google_Cloud_Platform_Service_Account\n$end"
[[ ! -z "$Google_OAuth_Access_Token" ]] && echo -e $green"{~} Google OAuth Access-Token : " "$red$Google_OAuth_Access_Token\n$end"
[[ ! -z "$Heroku_API_Key" ]] && echo -e $green"{~} Heroku APIkey : " "$red$Heroku_API_Key\n$end"
[[ ! -z "$IP_Address" ]] && echo -e $green"{~} IP_Address : " "$red$IP_Address\n$end"
[[ ! -z "$LinkFinder" ]] && echo -e $green"{~} LinkFinder : " "$red$LinkFinder\n$end"
[[ ! -z "$MailChimp_API_Key" ]] && echo -e $green"{~} MailChimp APIkey : " "$red$MailChimp_API_Key\n$end"
[[ ! -z "$Mailgun_API_Key" ]] && echo -e $green"{~} Mailgun APIkey : " "$red$Mailgun_API_Key\n$end"
[[ ! -z "$Password_in_URL" ]] && echo -e $green"{~} Password in URL: " "$red$Password_in_URL\n$end"
[[ ! -z "$PayPal_Braintree_Access_Token" ]] && echo -e $green"{~} PayPal Braintree Access Token : " "$red$PayPal_Braintree_Access_Token\n$end"
[[ ! -z "$Picatic_API_Key" ]] && echo -e $green"{~} Picatic APIkey : " "$red$Picatic_API_Key\n$end"
[[ ! -z "$Slack_Webhook" ]] && echo -e $green"{~} Slack Webhook : " "$red$Slack_Webhook\n$end"
[[ ! -z "$Stripe_API_Key" ]] && echo -e $green"{~} Stripe APIkey : " "$red$Stripe_API_Key\n$end"
[[ ! -z "$Stripe_Restricted_API_Key" ]] && echo -e $green"{~} Stripe-Restricted APIkey : " "$red$Stripe_Restricted_API_Key\n$end"
[[ ! -z "$Square_Access_Token" ]] && echo -e $green"{~} Square Access Token : " "$red$Square_Access_Token\n$end"
[[ ! -z "$Square_OAuth_Secret" ]] && echo -e $green"{~} Square_OAuth_Secret : " "$red$Square_OAuth_Secret\n$end"
[[ ! -z "$Twilio_API_Key" ]] && echo -e $green"{~} Twilio APIkey : " "$red$Twilio_API_Key\n$end"
[[ ! -z "$Twitter_ClientID" ]] && echo -e $green"{~} Twitter ClientID : " "$red$Twitter_ClientID\n$end"
[[ ! -z "$Twitter_Access_Token" ]] && echo -e $green"{~} Twitter Access Token : " "$red$Twitter_Access_Token\n$end"
[[ ! -z "$Twitter_Secret_Key" ]] && echo -e $green"{~} Twitter Secret key : " "$red$Twitter_Secret_Key\n$end"
[[ ! -z "$Twitter_OAuth" ]] && echo -e $green"{~} Twitter OAuth : " "$red$Twitter_OAuth\n$end"
[[ ! -z "$Artifactory_API_Token" ]] && echo -e $green"{~} Artifactory API-Token : " "$red$Artifactory_API_Token\n$end"
# [[ ! -z "$Artifactory_Password" ]] && echo -e $green"{~} Artifactory Password : " "$red$Artifactory_Password\n$end"
[[ ! -z "$Basic_Auth_Credentials" ]] && echo -e $green"{~} Basic Auth Credentials : " "$red$Basic_Auth_Credentials\n$end"
[[ ! -z "$Cloudinary_Basic_Auth" ]] && echo -e $green"{~} Cloudinary-Basic Auth : " "$red$Cloudinary_Basic_Auth\n$end"
[[ ! -z "$Mailto" ]] && echo -e "$redMailto : " $green"{~} $Mailto\n$end"
[[ ! -z "$Amazon_AWS_S3_Bucket_1st" ]] && echo -e $green"{~} Amazon AWS_S3 Bucket : " "$red$Amazon_AWS_S3_Bucket_1st\n$end"
[[ ! -z "$Amazon_AWS_S3_Bucket_3rd" ]] && echo -e $green"{~} Amazon AWS_S3 Bucket : " "$red$Amazon_AWS_S3_Bucket_3rd\n$end"
[[ ! -z "$Amazon_AWS_S3_Bucket_2nd" ]] && echo -e $green"{~} Amazon AWS_S3 Bucket : " "$red$Amazon_AWS_S3_Bucket_2nd\n$end"
[[ ! -z "$Amazon_AWS_S3_Bucket_4th" ]] && echo -e $green"{~} Amazon AWS_S3 Bucket : " "$red$Amazon_AWS_S3_Bucket_4th\n$end"
[[ ! -z "$Amazon_AWS_S3_Bucket_5th" ]] && echo -e $green"{~} Amazon AWS_S3 Bucket : " "$red$Amazon_AWS_S3_Bucket_5th\n$end"
[[ ! -z "$Amazon_AWS_S3_Bucket_6th" ]] && echo -e $green"{~} Amazon AWS_S3 Bucket : " "$red$Amazon_AWS_S3_Bucket_6th\n$end"
}

apk=$1

apkname=$(echo $apk | awk -F .apk '{print $1}')

echo -e "$red{~}$green Running apktool against this apk : $red$apk"$end
echo -e "$red{-}$green Output Directory name : $red$apkname"$end

apktool d $apk -f -o $apkname
echo -e $red"{+} Find regexs file..$end"
cd $apkname;
run_regex

echo -e "$red{~}$green You can manually check this thing :" $red"HTTPS_Protocol HTTP_Protocol Artifactory_Password Authorization_Basic ipv6 !"$end

