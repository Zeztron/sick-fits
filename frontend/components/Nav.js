import Link from 'next/link';
import NavStyles from './styles/NavStyles';
import User from './User';

const Nav = () => (
    <User>
        {({data: { me }}) => (
            <NavStyles>
                <Link href="/items">
                    <a>shop</a>
                </Link>
                {me && (
                    <>
                        <Link href="/sell">
                            <a>sell</a>
                        </Link>
                        <Link href="/orders">
                            <a>orders</a>
                        </Link>
                        <Link href="/me">
                            <a>account</a>
                        </Link>
                    </>
                )}
                {!me && (
                    <Link href="/signup">
                        <a>signin</a>
                    </Link>
                )}
            </NavStyles>
        )}
    </User>  
)

export default Nav;