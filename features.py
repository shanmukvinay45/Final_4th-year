import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

# Initialize global variables that will be used across functions
def initialize_data(url):
    data = {
        'url': url,
        'domain': "",
        'whois_response': "",
        'urlparse': "",
        'response': "",
        'soup': ""
    }
    
    try:
        data['response'] = requests.get(url)
        data['soup'] = BeautifulSoup(data['response'].text, 'html.parser')
    except:
        pass

    try:
        data['urlparse'] = urlparse(url)
        data['domain'] = data['urlparse'].netloc
    except:
        pass

    try:
        data['whois_response'] = whois.whois(data['domain'])
    except:
        pass
    
    return data

# 1.UsingIp
def using_ip(data):
    try:
        ipaddress.ip_address(data['url'])
        return -1
    except:
        return 1

# 2.longUrl
def long_url(data):
    if len(data['url']) < 54:
        return 1
    if len(data['url']) >= 54 and len(data['url']) <= 75:
        return 0
    return -1

# 3.shortUrl
def short_url(data):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', data['url'])
    if match:
        return -1
    return 1

# 4.Symbol@
def symbol(data):
    if re.findall("@", data['url']):
        return -1
    return 1

# 5.Redirecting//
def redirecting(data):
    if data['url'].rfind('//') > 6:
        return -1
    return 1

# 6.prefixSuffix
def prefix_suffix(data):
    try:
        match = re.findall('\-', data['domain'])
        if match:
            return -1
        return 1
    except:
        return -1

# 7.SubDomains
def sub_domains(data):
    dot_count = len(re.findall("\.", data['url']))
    if dot_count == 1:
        return 1
    elif dot_count == 2:
        return 0
    return -1

# 8.HTTPS
def https(data):
    try:
        https_scheme = data['urlparse'].scheme
        if 'https' in https_scheme:
            return 1
        return -1
    except:
        return 1

# 9.DomainRegLen
def domain_reg_len(data):
    try:
        expiration_date = data['whois_response'].expiration_date
        creation_date = data['whois_response'].creation_date
        try:
            if(len(expiration_date)):
                expiration_date = expiration_date[0]
        except:
            pass
        try:
            if(len(creation_date)):
                creation_date = creation_date[0]
        except:
            pass

        age = (expiration_date.year-creation_date.year)*12 + (expiration_date.month-creation_date.month)
        if age >= 12:
            return 1
        return -1
    except:
        return -1

# 10. Favicon
def favicon(data):
    try:
        for head in data['soup'].find_all('head'):
            for head.link in data['soup'].find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                if data['url'] in head.link['href'] or len(dots) == 1 or data['domain'] in head.link['href']:
                    return 1
        return -1
    except:
        return -1

# 11. NonStdPort
def non_std_port(data):
    try:
        port = data['domain'].split(":")
        if len(port) > 1:
            return -1
        return 1
    except:
        return -1

# 12. HTTPSDomainURL
def https_domain_url(data):
    try:
        if 'https' in data['domain']:
            return -1
        return 1
    except:
        return -1

# 13. RequestURL
def request_url(data):
    try:
        i, success = 0, 0
        for img in data['soup'].find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if data['url'] in img['src'] or data['domain'] in img['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for audio in data['soup'].find_all('audio', src=True):
            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
            if data['url'] in audio['src'] or data['domain'] in audio['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for embed in data['soup'].find_all('embed', src=True):
            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
            if data['url'] in embed['src'] or data['domain'] in embed['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for iframe in data['soup'].find_all('iframe', src=True):
            dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
            if data['url'] in iframe['src'] or data['domain'] in iframe['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        try:
            percentage = success/float(i) * 100
            if percentage < 22.0:
                return 1
            elif((percentage >= 22.0) and (percentage < 61.0)):
                return 0
            else:
                return -1
        except:
            return 0
    except:
        return -1

# 14. AnchorURL
def anchor_url(data):
    try:
        i, unsafe = 0, 0
        for a in data['soup'].find_all('a', href=True):
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (data['url'] in a['href'] or data['domain'] in a['href']):
                unsafe = unsafe + 1
            i = i + 1

        try:
            percentage = unsafe / float(i) * 100
            if percentage < 31.0:
                return 1
            elif ((percentage >= 31.0) and (percentage < 67.0)):
                return 0
            else:
                return -1
        except:
            return -1
    except:
        return -1

# 15. LinksInScriptTags
def links_in_script_tags(data):
    try:
        i, success = 0, 0
    
        for link in data['soup'].find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if data['url'] in link['href'] or data['domain'] in link['href'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for script in data['soup'].find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if data['url'] in script['src'] or data['domain'] in script['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        try:
            percentage = success / float(i) * 100
            if percentage < 17.0:
                return 1
            elif((percentage >= 17.0) and (percentage < 81.0)):
                return 0
            else:
                return -1
        except:
            return 0
    except:
        return -1

# 16. ServerFormHandler
def server_form_handler(data):
    try:
        if len(data['soup'].find_all('form', action=True)) == 0:
            return 1
        else:
            for form in data['soup'].find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif data['url'] not in form['action'] and data['domain'] not in form['action']:
                    return 0
                else:
                    return 1
    except:
        return -1

# 17. InfoEmail
def info_email(data):
    try:
        if re.findall(r"[mail\(\)|mailto:?]", data['soup']):
            return -1
        else:
            return 1
    except:
        return -1

# 18. AbnormalURL
def abnormal_url(data):
    try:
        if data['response'].text == data['whois_response']:
            return 1
        else:
            return -1
    except:
        return -1

# 19. WebsiteForwarding
def website_forwarding(data):
    try:
        if len(data['response'].history) <= 1:
            return 1
        elif len(data['response'].history) <= 4:
            return 0
        else:
            return -1
    except:
        return -1

# 20. StatusBarCust
def status_bar_cust(data):
    try:
        if re.findall("<script>.+onmouseover.+</script>", data['response'].text):
            return 1
        else:
            return -1
    except:
        return -1

# 21. DisableRightClick
def disable_right_click(data):
    try:
        if re.findall(r"event.button ?== ?2", data['response'].text):
            return 1
        else:
            return -1
    except:
        return -1

# 22. UsingPopupWindow
def using_popup_window(data):
    try:
        if re.findall(r"alert\(", data['response'].text):
            return 1
        else:
            return -1
    except:
        return -1

# 23. IframeRedirection
def iframe_redirection(data):
    try:
        if re.findall(r"[<iframe>|<frameBorder>]", data['response'].text):
            return 1
        else:
            return -1
    except:
        return -1

# 24. AgeofDomain
def age_of_domain(data):
    try:
        creation_date = data['whois_response'].creation_date
        try:
            if(len(creation_date)):
                creation_date = creation_date[0]
        except:
            pass

        today = date.today()
        age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
        if age >= 6:
            return 1
        return -1
    except:
        return -1

# 25. DNSRecording    
def dns_recording(data):
    try:
        creation_date = data['whois_response'].creation_date
        try:
            if(len(creation_date)):
                creation_date = creation_date[0]
        except:
            pass

        today = date.today()
        age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
        if age >= 6:
            return 1
        return -1
    except:
        return -1

# 26. WebsiteTraffic   
def website_traffic(data):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + data['url']).read(), "xml").find("REACH")['RANK']
        if (int(rank) < 100000):
            return 1
        return 0
    except:
        return -1

# 27. PageRank
def page_rank(data):
    try:
        prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": data['domain']})
        global_rank = int(re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)[0])
        if global_rank > 0 and global_rank < 100000:
            return 1
        return -1
    except:
        return -1

# 28. GoogleIndex
def google_index(data):
    try:
        site = search(data['url'], 5)
        if site:
            return 1
        else:
            return -1
    except:
        return 1

# 29. LinksPointingToPage
def links_pointing_to_page(data):
    try:
        number_of_links = len(re.findall(r"<a href=", data['response'].text))
        if number_of_links == 0:
            return 1
        elif number_of_links <= 2:
            return 0
        else:
            return -1
    except:
        return -1

# 30. StatsReport
def stats_report(data):
    try:
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', data['url'])
        ip_address = socket.gethostbyname(data['domain'])
        ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
        if url_match:
            return -1
        elif ip_match:
            return -1
        return 1
    except:
        return 1

# Main function to extract all features
def extract_features(url):
    data = initialize_data(url)
    features = []
    
    features.append(using_ip(data))
    features.append(long_url(data))
    features.append(short_url(data))
    features.append(symbol(data))
    features.append(redirecting(data))
    features.append(prefix_suffix(data))
    features.append(sub_domains(data))
    features.append(https(data))
    features.append(domain_reg_len(data))
    features.append(favicon(data))
    
    features.append(non_std_port(data))
    features.append(https_domain_url(data))
    features.append(request_url(data))
    features.append(anchor_url(data))
    features.append(links_in_script_tags(data))
    features.append(server_form_handler(data))
    features.append(info_email(data))
    features.append(abnormal_url(data))
    features.append(website_forwarding(data))
    features.append(status_bar_cust(data))
    
    features.append(disable_right_click(data))
    features.append(using_popup_window(data))
    features.append(iframe_redirection(data))
    features.append(age_of_domain(data))
    features.append(dns_recording(data))
    features.append(website_traffic(data))
    features.append(page_rank(data))
    features.append(google_index(data))
    features.append(links_pointing_to_page(data))
    features.append(stats_report(data))
    
    return features
import logging

# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create a file handler and a stream handler
file_handler = logging.FileHandler('phishing_detector.log')
stream_handler = logging.StreamHandler()

# Create a formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# Initialize global variables that will be used across functions
def initialize_data(url):
    data = {
        'url': url,
        'domain': "",
        'whois_response': "",
        'urlparse': "",
        'response': "",
        'soup': ""
    }
    
    try:
        data['response'] = requests.get(url)
        data['soup'] = BeautifulSoup(data['response'].text, 'html.parser')
        logger.info('Initialized data for URL: %s', url)
    except Exception as e:
        logger.error('Failed to initialize data for URL: %s - %s', url, str(e))
        pass

    try:
        data['urlparse'] = urlparse(url)
        data['domain'] = data['urlparse'].netloc
        logger.info('Parsed URL: %s', url)
    except Exception as e:
        logger.error('Failed to parse URL: %s - %s', url, str(e))
        pass

    try:
        data['whois_response'] = whois.whois(data['domain'])
        logger.info('Retrieved WHOIS data for domain: %s', data['domain'])
    except Exception as e:
        logger.error('Failed to retrieve WHOIS data for domain: %s - %s', data['domain'], str(e))
        pass
    
    return data

# ... (rest of the code remains the same)

# Main function to extract all features
def extract_features(url):
    data = initialize_data(url)
    features = []
    
    features.append(using_ip(data))
    features.append(long_url(data))
    features.append(short_url(data))
    features.append(symbol(data))
    features.append(redirecting(data))
    features.append(prefix_suffix(data))
    features.append(sub_domains(data))
    features.append(https(data))
    features.append(domain_reg_len(data))
    features.append(favicon(data))
    
    features.append(non_std_port(data))
    features.append(https_domain_url(data))
    features.append(request_url(data))
    features.append(anchor_url(data))
    features.append(links_in_script_tags(data))
    features.append(server_form_handler(data))
    features.append(info_email(data))
    features.append(abnormal_url(data))
    features.append(website_forwarding(data))
    features.append(status_bar_cust(data))
    
    features.append(disable_right_click(data))
    features.append(using_popup_window(data))
    features.append(iframe_redirection(data))
    features.append(age_of_domain(data))
    features.append(dns_recording(data))
    features.append(website_traffic(data))
    features.append(page_rank(data))
    features.append(google_index(data))
    features.append(links_pointing_to_page(data))
    features.append(stats_report(data))
    
    logger.info('Extracted features for URL: %s', url)
    return features


url = "yurika.otakuthon.com/reg/main.pl/en/"
features = extract_features(url)
print(features)