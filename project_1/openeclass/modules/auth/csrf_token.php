<?php session_start();


/* Generates CSRF token if it's not already exists in SESSION array else
 return the existing token */
 function generateToken($token_name='csrf_token') {

    if (!isset($_SESSION[$token_name])) {
        $token = bin2hex(openssl_random_pseudo_bytes(32));
        $_SESSION[$token_name] = $token;
    } 
    else {
        $token = $_SESSION[$token_name];
    }
    
    return $token;
}


/* Validates CSRF token and unsets it if $unset is TRUE 
(FALSE only for spesific pages that dont refresh on submit) */
function validateToken($token, $tok_name='csrf_token', $unset=TRUE){

    $request = $_SERVER['REQUEST_METHOD'];

    if ($request === 'POST') {

        if (!isset($_POST['csrf_token']) || !isset($token)){
            invalidate_token();
            return FALSE;
        }
        if ($_POST['csrf_token'] !== $token){
            invalidate_token();
            return FALSE;
        }

        if ($_POST['csrf_token'] === $token){
            if ($unset) unset($_SESSION[$tok_name]);
            return TRUE;
        }
    }
    
    elseif ($request === 'GET') {
        
        if (!isset($_GET['csrf_token']) || !isset($token)){
            invalidate_token();
            return FALSE;
        }
        if ($_GET['csrf_token'] !== $token){
            invalidate_token();
            return FALSE;
        }
        if ($_GET['csrf_token'] === $token){
            if ($unset) unset($_SESSION[$tok_name]);
            return TRUE;
        }
    }

    return FALSE;
}


/* Verifies the Token only based on _SESSION and token parameter */
function verifyToken($token, $tok_name='csrf_token'){
    
    if ($_SESSION[$tok_name] !== $token){
        invalidate_token();
        return FALSE;
    }

    return TRUE;
}


/* Draw a gif if CSRF token validation/verification fails */
function invalidate_token(){
    exit("<h2> Invalid or missing CSRF token </h2>");
}


?>