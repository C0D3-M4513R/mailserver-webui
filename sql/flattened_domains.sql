CREATE OR REPLACE VIEW flattened_domains AS
    with recursive test as (
        select
            virtual_domains.id AS id,
            virtual_domains.super AS super
        from virtual_domains
        union all
        select
            domain.id AS id,
            test.super AS super
        from virtual_domains domain
        join test on domain.super = test.id and test.id != test.super
    ) select * from test;