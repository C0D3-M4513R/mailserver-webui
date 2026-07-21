use crate::rocket::response::Return;

#[actix_web::post("/logout")]
pub async fn logout_post(req: actix_web::HttpRequest) -> Return {
    let mut ret = Return::redirect_to_value(actix_web::http::header::HeaderValue::from_static("/"));

    let mut cookie = match req.cookie("email") {
        Some(v) => v,
        None => return ret,
    };
    
    cookie.make_removal();
    ret.add_cookie(&cookie);

    ret
}