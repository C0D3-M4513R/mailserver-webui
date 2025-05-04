#[derive(thiserror::Error, Debug)]
pub enum TemplateError {
    #[error("Template could not be rendered, because: {0}")]
    AskamaError(#[from] askama::Error),
}