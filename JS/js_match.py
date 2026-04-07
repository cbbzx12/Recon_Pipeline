import re
import os
import sys
from collections import defaultdict
import chardet

# 保留原有的所有正则表达式模式（完全未改动）
regex_patterns = [
    # 原始路径匹配
    (r'''(['"]\/[^][^>< \)\(\{\}]*?['"])''', "path"),
    
    # 邮箱匹配
    (r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', "email"),
    
    # 手机号匹配
    (r'(?<!\d)(13\d{9}|14[579]\d{8}|15[^4\D]\d{8}|166\d{8}|17[^49\D]\d{8}|18\d{9}|19[189]\d{8})(?!\d)', "phone"),
    
    # 身份证匹配
    (r'\b\d{17}[\dXx]|\b\d{14}\d{1}|\b\d{17}[\dXx]', "id_card"),
    
    # IP匹配
    (r'\d+\.\d+\.\d+\.\d+', "ip"),
    
    # 密码匹配小正则
    (r'(?:^|_)((?:username|password|key|auv)_)\s*[:=><]*\s*["\']([^"\']+)["\']', "password_simple"),
    
    # 匹配信息大正则
    (r'(?i)((access_key|username|user|jwtkey|jwt_key|AESKEY|AES_KEY|appsecret|app_secret|access_token|password|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|phone|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api\.googlemaps\s+AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc\ password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn\.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encsearch_password|encryption_key|encryption_password|env\.heroku_api_key|env\.sonatype_password|eureka\.awssecretkey)\s*[:=><]{1,2}\s*[\"\']{0,1}([0-9a-zA-Z\-_=+/]{8,64})[\"\']{0,1})', "sensitive_info"),
    
    # 常见的云AK匹配
    (r'''(['"]\s*(?:GOOG[\w\W]{10,30}|AZ[A-Za-z0-9]{34,40}|AKID[A-Za-z0-9]{13,20}|AKIA[A-Za-z0-9]{16}|IBM[A-Za-z0-9]{10,40}|OCID[A-Za-z0-9]{10,40}|LTAI[A-Za-z0-9]{12,20}|AK[\w\W]{10,62}|AK[A-Za-z0-9]{10,40}|AK[A-Za-z0-9]{10,40}|UC[A-Za-z0-9]{10,40}|QY[A-Za-z0-9]{10,40}|KS3[A-Za-z0-9]{10,40}|LTC[A-Za-z0-9]{10,60}|YD[A-Za-z0-9]{10,60}|CTC[A-Za-z0-9]{10,60}|YYT[A-Za-z0-9]{10,60}|YY[A-Za-z0-9]{10,40}|CI[A-Za-z0-9]{10,40}|gcore[A-Za-z0-9]{10,30})\s*['"])''', "cloud_ak"),
    
    # 谷歌云 AccessKey ID匹配
    (r'\bAIza[0-9A-Za-z_\-]{35}\b', "google_cloud_key"),
    
    # 金山云 AccessKey ID匹配
    (r'\bAKLT[a-zA-Z0-9-_]{16,28}\b', "ksyun_key"),
    
    # 火山引擎 AccessKey ID匹配
    (r'\b(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}\b', "volcano_key"),
    
    # 亚马逊 AccessKey ID匹配
    (r'["\'](?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}["\']', "aws_key"),
    
    # 京东云 AccessKey ID匹配
    (r'\bJDC_[0-9A-Z]{25,40}\b', "jdcloud_key"),
    
    # JWT Token匹配
    (r'eyJ[A-Za-z0-9_/+\-]{10,}={0,2}\.[A-Za-z0-9_/+\-\\]{15,}={0,2}\.[A-Za-z0-9_/+\-\\]{10,}={0,2}', "jwt_token"),
    
    # PRIVATE KEY匹配
    (r'-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[a-zA-Z0-9\/\n\r=+]*-----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----', "private_key"),
    
    # Auth Token匹配
    (r'["\'$$]*[Aa]uthorization["\'$$]*\s*[:=]\s*[\'"]?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}[\'"]?', "auth_token"),
    
    # Basic Token匹配
    (r'\b[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}\b', "basic_token"),
    
    # Bearer Token匹配
    (r'\b[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}\b', "bearer_token"),
    
    # slack webhook匹配
    (r'\bhttps://hooks.slack.com/services/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{15,24}\b', "slack_webhook"),
    
    # 飞书 webhook匹配
    (r'\bhttps://open.feishu.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}\b', "feishu_webhook"),
    
    # 钉钉 webhook匹配
    (r'\bhttps://oapi.dingtalk.com/robot/send\?access_token=[a-z0-9]{50,80}\b', "dingtalk_webhook"),
    
    # 企业微信 webhook匹配
    (r'\bhttps://qyapi.weixin.qq.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}\b', "wecom_webhook"),
    
    # 微信公众号匹配
    (r'["\'](gh_[a-z0-9]{11,13})["\']', "wechat_public"),
    
    # 企业微信 corpid匹配
    (r'["\'](ww[a-z0-9]{15,18})["\']', "wecom_corpid"),
    
    # 微信 公众号/小程序 APPID匹配
    (r'["\'](wx[a-z0-9]{15,18})["\']', "wechat_appid"),
    
    # 腾讯云 API网关 APPKEY匹配
    (r'\bAPID[a-zA-Z0-9]{32,42}\b', "tencent_apigw"),
    
    # grafana service account token匹配1
    (r'\b(?:VUE|APP|REACT)_[A-Z_0-9]{1,15}_(?:KEY|PASS|PASSWORD|TOKEN|APIKEY)[\'"]*[:=]"(?:[A-Za-z0-9_\-]{15,50}|[a-z0-9/+]{50,100}==?)"', "grafana_token1"),
    
    # grafana service account token匹配2
    (r'\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b', "grafana_token2"),
    
    # grafana cloud api token匹配
    (r'\bglc_[A-Za-z0-9\-_+/]{32,200}={0,2}\b', "grafana_cloud"),
    
    # grafana api key匹配
    (r'\beyJrIjoi[a-zA-Z0-9\-_+/]{50,100}={0,2}\b', "grafana_key"),
    
    # Github Token匹配
    (r'\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b', "github_token"),
    
    # Gitlab V2 Token匹配
    (r'\b(glpat-[a-zA-Z0-9\-=_]{20,22})\b', "gitlab_token"),
    
    # 注释
    (r'\*/(.*)', "comment_block_end"),      # 匹配 */ 后的注释内容
    (r'//[^\n]*', "comment_line"),         # 匹配 // 单行注释
    (r'/\*(.*)', "comment_block_start"),   # 匹配 /* 后的注释内容
    (r'<!--(?:.|\n)*?-->', "html_comment"), # 匹配 HTML 注释

    # 复杂单词/短语匹配
    (r'[a-zA-Z]+[\w-]*\d*|\d+[\w-]*[a-zA-Z]+|[a-zA-Z]+\.[a-zA-Z]+|\w+\.\d+|[a-zA-Z]+~[a-zA-Z]+|\w+~\d+|\d+-\d+|[a-zA-Z]+-[a-zA-Z]+', "word_phrase")
]

def detect_encoding(file_path):
    """自动检测文件编码"""
    with open(file_path, 'rb') as f:
        rawdata = f.read(1024)  # 只读取前1024字节来检测编码
        result = chardet.detect(rawdata)
        return result['encoding'] or 'gb18030'

def scan_directory(directory):
    """扫描目录并返回文件列表"""
    file_list = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_list.append(file_path)
    return file_list

def analyze_file(file_path):
    """分析单个文件"""
    results = defaultdict(list)
    try:
        encoding = detect_encoding(file_path)
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            content = f.read()
            for pattern, pattern_type in regex_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    for match in matches:
                        if isinstance(match, tuple):
                            match = next((m for m in match if m), "")
                        match = str(match).strip('"\'').strip()
                        if match:
                            results[pattern_type].append(f"{os.path.basename(file_path)}: {match}")
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {str(e)}")
    return results

def save_results_by_type(all_results, output_dir):
    """按类型保存结果到不同文件"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    type_results = defaultdict(list)
    for file_results in all_results.values():
        for pattern_type, matches in file_results.items():
            type_results[pattern_type].extend(matches)
    
    for pattern_type, matches in type_results.items():
        output_file = os.path.join(output_dir, f"{pattern_type}.txt")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(set(matches))))
    
    print(f"结果已按类型保存到目录: {output_dir}")

def main():
    if len(sys.argv) != 3:
        print("用法: python script.py <输入目录> <输出目录>")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    if not os.path.isdir(input_dir):
        print(f"错误: {input_dir} 不是有效目录")
        sys.exit(1)
    
    file_list = scan_directory(input_dir)
    all_results = {}
    
    print(f"开始扫描目录: {input_dir}")
    print(f"找到 {len(file_list)} 个文件...")
    
    for file_path in file_list:
        all_results[file_path] = analyze_file(file_path)
    
    save_results_by_type(all_results, output_dir)

if __name__ == "__main__":
    main()