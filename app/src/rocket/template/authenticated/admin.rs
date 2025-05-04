use askama::Template;

#[derive(Template)]
#[template(path = "authenticated/admin.html")]
pub struct Admin<'a>{
    pub domains: &'a[ &'a String]
}