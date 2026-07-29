useEffect(() => {
  const fetchProfile = async () => {
    const token = localStorage.getItem('token');
    const response = await axios.get('http://127.0.0.1:5000/api/user/profile', {
      headers: { Authorization: `Bearer ${token}` }
    });
    setUser(response.data.user);
  };
  fetchProfile();
}, []);