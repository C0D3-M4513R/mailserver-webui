use syn::__private::ToTokens;
use syn::punctuated::Punctuated;
use syn::Token;

#[proc_macro]
pub fn add_uint(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input: Punctuated<syn::LitInt, Token![,]> = syn::parse_quote!(_input);
    let vec = input.iter().map(syn::LitInt::base10_digits)
        .fold(Vec::new(), |mut a, b| {
            let mut carry = 0;
            let mut index = 0;
            if a.len() < b.len() {
                a.resize(b.len(), 0);
            }
            for chr in b.chars(){
                let v = chr.to_digit(10).expect("Invalid digit in input");
                a[index] += v + carry;
                carry = a[index] / 10;
                a[index] %= 10;
                index+=1;
            }
            a
        });
    let mut carry = 0;
    let string = vec.into_iter().fold(String::new(), |mut a, mut b|{
        b = b + carry;
        carry = b / 10;
        b=b%10;
        a.push(char::from_digit(b, 10).expect("Invalid digit in input"));
        a
    });

    let mut ts = proc_macro2::TokenStream::new();
    syn::LitStr::new(&string, proc_macro2::Span::call_site()).to_tokens(&mut ts);
    ts.into()
}