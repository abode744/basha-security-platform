from app.scope import validate,in_scope,validate_url
def test_scope_boundary():
 r,i,e=validate('example.com',['*.example.com'],[]);assert in_scope('api.example.com',r,i,e);assert not in_scope('example.com.attacker.com',r,i,e);assert not validate_url('https://example.com.attacker.com/x',r,i,e);assert not validate_url('https://u:p@example.com/x',r,i,e)
def test_exclusion():
 r,i,e=validate('example.com',['*.example.com'],['admin.example.com']);assert not in_scope('admin.example.com',r,i,e)
