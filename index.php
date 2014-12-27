<?php
ini_set('display_errors', 'On');
error_reporting(E_ALL | E_STRICT);

    $values;

    parse_str($_SERVER['QUERY_STRING'], $values);

    $realm = !isset_or($values["realm"], null) ? 'relying_party_not_specified' : $values["realm"];
    $reply = $values["redirect_uri"];
    $deflate = $values["deflate"] == 'true' ? true : false;

    // need to build an actual identity...
    $identity = new stdClass();
    $identity->claims = array();
    $identity->claims[0] = new stdClass();
    $identity->claims[0]->claimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name';
    $identity->claims[0]->value = 'admin';
    //$identity->claims[0]->value = 'someexternaluser';
    $identity->claims[1] = new stdClass();
    $identity->claims[1]->claimType = SitefinityClaimTypes::Domain;
    $identity->claims[1]->value = 'Default';
    //$identity->claims[1]->value = 'SomeCustomMembershipProvider';

    $issuer = 'http://' . "{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
    
    if (strpos($issuer, '?')) {
        $idx = strpos($issuer, '?');
        $issuer = substr($issuer, 0, $idx);
    }

    $token = createToken($identity->claims, $issuer, $realm);

    $queryString;

    if (!isNullOrEmptyString($reply)) {
        $path = '';
        
        if (strpos($reply, '?')) {
            $idx = strpos($reply, '?');
            $path = substr($reply, 0, $idx);
            parse_str(substr($reply, $idx + 1), $queryString);
        } else {
            $path = $reply;
            $queryString = null;
        }

        $swt = wrapSWT($token, $deflate);
        $path = $path . '?wrap_deflated=' . $swt['wrap_deflated'] . '&wrap_access_token=' . $swt['wrap_access_token'] . '&wrap_access_token_expires_in=' . $swt['wrap_access_token_expires_in'];

        $uri = $realm . ltrim($path, '/');

        header('Location: ' . $uri);
        return;
    }

    $queryString = array();
    wrapSWT($queryString, $token, $deflate);

    ob_clean();
    http_response_code(200);
    header('Content-Type: application/x-www-form-urlencoded');
    echo toQueryString($queryString, false);
    

    function createToken($claims, $issuerName, $appliesTo)
    {
        $appliesTo = strtolower($appliesTo);

        $key = 'F582C2CB2BFC309AB1CD19F970B3A5C1D959C34276AC188BF5C1358B08506E25';

        $unsignedToken = '';
        
        foreach ($claims as $c) {
            $unsignedToken .= sprintf("%s=%s&", urlencode($c->claimType), urlencode($c->value));
        }

        //$unsignedToken .= sprintf("%s=%s&", SitefinityClaimTypes::StsType, "wa");

        $loginDateClaim = null;

        foreach ($claims as $c) {
            if (SitefinityClaimTypes::LastLoginDate == $c->claimType) {
                $loginDateClaim = $c;
                break;
            }
        }

        $issueDate = new DateTime('now', new DateTimeZone('UTC'));

        if ($loginDateClaim != null) {
            $date = date_parse_from_format('dddd, MMMM dd, yyyy h:mm:ss tt', $loginDateClaim->value);
            if (!empty($date)) {
                $issueDate = gmdate('Y-m-d H:i:s');
            }
        }

        $lifeTimeInSeconds = 3600;

        $unsignedToken .= sprintf('TokenId=%s&', urlencode(getGUID()));
        $unsignedToken .= sprintf('Issuer=%s&', urlencode($issuerName));
        $unsignedToken .= sprintf('Audience=%s&', urlencode($appliesTo));
        $unsignedToken .= sprintf('ExpiresOn=%s', $issueDate->add(new DateInterval('PT' . $lifeTimeInSeconds . 'S'))->getTimestamp());

        $sig = hash_hmac('sha256', $unsignedToken, pack("H*", $key), true);

        $originalSig = urlencode(base64_encode($sig));
        $modifiedSig = preg_replace_callback('/%[0-9A-F]{2}/', function(array $matches)
        {
            return strtolower($matches[0]);
        }, $originalSig);

        $signedToken = sprintf('%s&HMACSHA256=%s', $unsignedToken, $modifiedSig);
        $token = new stdClass();
        $token->rawToken = $signedToken;
        $token->validFrom = $issueDate->getTimestamp();
        $token->validTo = $issueDate->add(new DateInterval('PT' . $lifeTimeInSeconds . 'S'))->getTimestamp();

        return $token;
    }

    function wrapSWT($token, $deflate) {
        $rawToken = $token->rawToken;
        $collection = array();

        if ($deflate) {
            $zipped = gzdeflate($rawToken);
            $rawToken = base64_encode($zipped);
            $collection["wrap_deflated"] = "true";
        }

        $collection["wrap_access_token"] = urlencode($rawToken);
        $seconds = (int)(($token->validTo) - ($token->validFrom));
        $collection["wrap_access_token_expires_in"] = (string)$seconds;

        return $collection;
    }

    function isset_or(&$check, $alternate = NULL) {
        return (isset($check)) ? $check : $alternate;
    }

    function getASCIIBytes($str) {
        return implode(unpack('C*', utf8_encode($str)));
    }

    function isNullOrEmptyString($str) {
        return (!isset($str) || trim($str) === '');
    }

    function endsWith($haystack, $needle) {
        return $needle === "" || strpos($haystack, $needle, strlen($haystack) - strlen($needle)) !== FALSE;
    }

    function getGUID() {
        if (function_exists('com_create_guid')) {
            return com_create_guid();
        } else {
            mt_srand((double)microtime()*10000);
            $charid = strtoupper(md5(uniqid(rand(), true)));
            $hyphen = chr(45);
            $uuid = substr($charid, 0, 8).$hyphen
                .substr($charid, 8, 4).$hyphen
                .substr($charid,12, 4).$hyphen
                .substr($charid,16, 4).$hyphen
                .substr($charid,20,12);
            return $uuid;
        }
    }

    function toQueryString($collection, $startWithQuestionMark = true) {
        if ($collection == null || empty($collection)) {
            return '';
        }

        $qs = '';

        if ($startWithQuestionMark) {
            $qs = '?';
        }

        $qs .= http_build_query($collection);

        return $qs;
    }

    abstract class SitefinityClaimTypes
    {
        const TokenId = "http://schemas.sitefinity.com/ws/2011/06/identity/claims/tokenid";
        const UserId = "http://schemas.sitefinity.com/ws/2011/06/identity/claims/userid";
        const Domain = "http://schemas.sitefinity.com/ws/2011/06/identity/claims/domain";
        const Role = "http://schemas.sitefinity.com/ws/2011/06/identity/claims/role";
        const IssueDate = "http://schemas.sitefinity.com/ws/2011/06/identity/claims/issuedate";
        const LastLoginDate = "http://schemas.sitefinity.com/ws/2011/06/identity/claims/lastlogindate";
        const Adjusted = "http://schemas.sitefinity.com/ws/2011/06/identity/claims/adjusted";
        const StsType = "http://schemas.sitefinity.com/ws/2011/06/identity/claims/ststype";
    }

?>
